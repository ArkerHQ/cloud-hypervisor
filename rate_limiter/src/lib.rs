// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
//! # Rate Limiter
//!
//! Provides a rate limiter written in Rust useful for IO operations that need to
//! be throttled.
//!
//! ## Behavior
//!
//! The rate limiter starts off as 'unblocked' with two token buckets configured
//! with the values passed in the `RateLimiter::new()` constructor.
//! All subsequent accounting is done independently for each token bucket based
//! on the `TokenType` used. If any of the buckets runs out of budget, the limiter
//! goes in the 'blocked' state. At this point an internal timer is set up which
//! will later 'wake up' the user in order to retry sending data. The 'wake up'
//! notification will be dispatched as an event on the FD provided by the `AsRawFD`
//! trait implementation.
//!
//! The contract is that the user shall also call the `event_handler()` method on
//! receipt of such an event.
//!
//! The token buckets are replenished every time a `consume()` is called, before
//! actually trying to consume the requested amount of tokens. The amount of tokens
//! replenished is automatically calculated to respect the `complete_refill_time`
//! configuration parameter provided by the user. The token buckets will never
//! replenish above their respective `size`.
//!
//! Each token bucket can start off with a `one_time_burst` initial extra capacity
//! on top of their `size`. This initial extra credit does not replenish and
//! can be used for an initial burst of data.
//!
//! The granularity for 'wake up' events when the rate limiter is blocked is
//! currently hardcoded to `100 milliseconds`.
//!
//! ## Limitations
//!
//! This rate limiter implementation relies on the *Linux kernel's timerfd* so its
//! usage is limited to Linux systems.
//!
//! Another particularity of this implementation is that it is not self-driving.
//! It is meant to be used in an external event loop and thus implements the `AsRawFd`
//! trait and provides an *event-handler* as part of its API. This *event-handler*
//! needs to be called by the user on every event on the rate limiter's `AsRawFd` FD.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use log::error;
use thiserror::Error;
use vmm_sys_util::timerfd::TimerFd;

/// Module for group rate limiting.
pub mod group;

#[derive(Error, Debug)]
/// Describes the errors that may occur while handling rate limiter events.
pub enum Error {
    /// The event handler was called spuriously.
    #[error("Event handler was called spuriously: {0}")]
    SpuriousRateLimiterEvent(&'static str),
    /// The event handler encounters while TimerFd::wait()
    #[error("Failed to wait for the timer")]
    TimerFdWaitError(#[source] std::io::Error),
}

// Interval at which the refill timer will run when limiter is at capacity.
const REFILL_TIMER_INTERVAL_MS: u64 = 100;
const TIMER_REFILL_DUR: Duration = Duration::from_millis(REFILL_TIMER_INTERVAL_MS);

const NANOSEC_IN_ONE_MILLISEC: u64 = 1_000_000;
const TOKEN_SCALE: u128 = 1_000_000_000;

/// Immutable parameters of one finite token bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketConfig {
    /// Number of tokens replenished in one refill period.
    pub size: u64,
    /// Initial extra tokens, granted once in this native instance.
    pub one_time_burst: u64,
    /// Refill period in milliseconds.
    pub refill_time: u64,
}

impl BucketConfig {
    /// Reject a disabled or arithmetically invalid finite configuration.
    pub fn validate(&self) -> io::Result<()> {
        if self.size == 0
            || self.refill_time == 0
            || self.refill_time > u64::MAX / NANOSEC_IN_ONE_MILLISEC
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid finite bucket",
            ));
        }
        Ok(())
    }
}

/// Last-accounted effective state of one bucket; observing it never refills it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BucketState {
    /// A finite configuration, or explicit unlimited.
    pub configured: Option<BucketConfig>,
    /// Remaining ordinary token credit.
    pub budget: u64,
    /// Remaining initial burst credit.
    pub burst: u64,
    /// Outstanding token debt rounded up, saturating at u64::MAX.
    pub debt: u64,
}

/// Effective state read from the actual consuming limiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimiterState {
    /// Byte accounting and policy.
    pub bandwidth: BucketState,
    /// Operation accounting and policy.
    pub ops: BucketState,
    /// Whether consumers currently wait for the timer.
    pub blocked: bool,
}

// Euclid's two-thousand-year-old algorithm for finding the greatest common divisor.
fn gcd(x: u64, y: u64) -> u64 {
    let mut x = x;
    let mut y = y;
    while y != 0 {
        let t = y;
        y = x % y;
        x = t;
    }
    x
}

/// Enum describing the outcomes of a `reduce()` call on a `TokenBucket`.
#[derive(Clone, Debug, PartialEq)]
pub enum BucketReduction {
    /// There are not enough tokens to complete the operation.
    Failure,
    /// A part of the available tokens have been consumed.
    Success,
    /// A number of tokens `inner` times larger than the bucket size have been consumed.
    OverConsumption(f64),
}

/// TokenBucket provides a lower level interface to rate limiting with a
/// configurable capacity, refill-rate and initial burst.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    // Bucket defining traits.
    size: u64,
    // Initial burst size (number of free initial tokens, that can be consumed at no cost)
    one_time_burst: u64,
    // Complete refill time in milliseconds.
    refill_time: u64,

    // Internal state descriptors.
    budget: u64,
    last_update: Instant,

    // Fields used for pre-processing optimizations.
    processed_capacity: u64,
    processed_refill_time: u64,
    configured_burst: u64,
    enabled: bool,
    // Fixed-point credit/debt belongs to the same bucket as its ordinary budget.
    debt: u128,
    fraction: u128,
}

impl TokenBucket {
    /// Creates a `TokenBucket` wrapped in an `Option`.
    ///
    /// TokenBucket created is of `size` total capacity and takes `complete_refill_time_ms`
    /// milliseconds to go from zero tokens to total capacity. The `one_time_burst` is initial
    /// extra credit on top of total capacity, that does not replenish and which can be used
    /// for an initial burst of data.
    ///
    /// If the `size` or the `complete refill time` are zero, then `None` is returned.
    pub fn new(size: u64, one_time_burst: u64, complete_refill_time_ms: u64) -> Option<Self> {
        // If either token bucket capacity or refill time is 0, disable limiting.
        if size == 0 || complete_refill_time_ms == 0 {
            return None;
        }
        // Formula for computing current refill amount:
        // refill_token_count = (delta_time * size) / (complete_refill_time_ms * 1_000_000)
        // In order to avoid overflows, simplify the fractions by computing greatest common divisor.

        let complete_refill_time_ns = complete_refill_time_ms * NANOSEC_IN_ONE_MILLISEC;
        // Get the greatest common factor between `size` and `complete_refill_time_ns`.
        let common_factor = gcd(size, complete_refill_time_ns);
        // The division will be exact since `common_factor` is a factor of `size`.
        let processed_capacity: u64 = size / common_factor;
        // The division will be exact since `common_factor` is a factor of `complete_refill_time_ns`.
        let processed_refill_time: u64 = complete_refill_time_ns / common_factor;

        Some(TokenBucket {
            size,
            one_time_burst,
            refill_time: complete_refill_time_ms,
            // Start off full.
            budget: size,
            // Last updated is now.
            last_update: Instant::now(),
            processed_capacity,
            processed_refill_time,
            configured_burst: one_time_burst,
            enabled: true,
            debt: 0,
            fraction: 0,
        })
    }

    fn configured(&self) -> Option<BucketConfig> {
        self.enabled.then_some(BucketConfig {
            size: self.size,
            one_time_burst: self.configured_burst,
            refill_time: self.refill_time,
        })
    }

    fn state(&self) -> BucketState {
        BucketState {
            configured: self.configured(),
            budget: self.budget,
            burst: self.one_time_burst,
            debt: u64::try_from(self.debt.div_ceil(TOKEN_SCALE)).unwrap_or(u64::MAX),
        }
    }

    fn settle_at(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_update)
            .as_nanos()
            .min(u128::from(u64::MAX));
        let numerator = elapsed * u128::from(self.size);
        let denominator = u128::from(self.refill_time) * u128::from(NANOSEC_IN_ONE_MILLISEC);
        let credit = (numerator / denominator)
            .saturating_mul(TOKEN_SCALE)
            .saturating_add((numerator % denominator) * TOKEN_SCALE / denominator);
        self.last_update = now;
        let repaid = credit.min(self.debt);
        self.debt -= repaid;
        if self.enabled {
            let available = (u128::from(self.budget) * TOKEN_SCALE + self.fraction)
                .saturating_add(credit - repaid)
                .min(u128::from(self.size) * TOKEN_SCALE);
            self.budget = (available / TOKEN_SCALE) as u64;
            self.fraction = available % TOKEN_SCALE;
        }
    }

    fn charge(&mut self, tokens: u64) {
        if !self.enabled {
            return;
        }
        let burst = tokens.min(self.one_time_burst);
        self.one_time_burst -= burst;
        let requested = u128::from(tokens - burst) * TOKEN_SCALE;
        let available = u128::from(self.budget) * TOKEN_SCALE + self.fraction;
        if requested > available {
            self.debt = self.debt.saturating_add(requested - available);
            self.budget = 0;
            self.fraction = 0;
        } else {
            self.budget = ((available - requested) / TOKEN_SCALE) as u64;
            self.fraction = (available - requested) % TOKEN_SCALE;
        }
    }

    fn debt_delay(&self) -> Option<Duration> {
        if !self.enabled || self.debt == 0 {
            return None;
        }
        let denominator = u128::from(self.refill_time) * u128::from(NANOSEC_IN_ONE_MILLISEC);
        let tokens = self.debt / TOKEN_SCALE;
        let fraction = self.debt % TOKEN_SCALE;
        let numerator = tokens
            .saturating_mul(denominator)
            .saturating_add((fraction * denominator).div_ceil(TOKEN_SCALE));
        let nanos = numerator.div_ceil(u128::from(self.size)).max(1);
        Some(Duration::from_nanos(
            u64::try_from(nanos).unwrap_or(u64::MAX),
        ))
    }

    /// Attempts to consume `tokens` from the bucket and returns whether the action succeeded.
    // TODO (Issue #259): handle cases where a single request is larger than the full capacity
    // for such cases we need to support partial fulfilment of requests
    pub fn reduce(&mut self, mut tokens: u64) -> BucketReduction {
        // First things first: consume the one-time-burst budget.
        if self.one_time_burst > 0 {
            // We still have burst budget for *all* tokens requests.
            if self.one_time_burst >= tokens {
                self.one_time_burst -= tokens;
                self.last_update = Instant::now();
                // No need to continue to the refill process, we still have burst budget to consume from.
                return BucketReduction::Success;
            }
            // We still have burst budget for *some* of the tokens requests.
            // The tokens left unfulfilled will be consumed from current `self.budget`.
            tokens -= self.one_time_burst;
            self.one_time_burst = 0;
        }

        // Compute time passed since last refill/update.
        let time_delta = self.last_update.elapsed().as_nanos() as u64;
        self.last_update = Instant::now();

        // At each 'time_delta' nanoseconds the bucket should refill with:
        // refill_amount = (time_delta * size) / (complete_refill_time_ms * 1_000_000)
        // `processed_capacity` and `processed_refill_time` are the result of simplifying above
        // fraction formula with their greatest-common-factor.
        self.budget += (time_delta * self.processed_capacity) / self.processed_refill_time;

        if self.budget >= self.size {
            self.budget = self.size;
        }

        if tokens > self.budget {
            // This operation requests a bandwidth higher than the bucket size
            if tokens > self.size {
                error!(
                    "Consumed {} tokens from bucket of size {}",
                    tokens, self.size
                );
                // Empty the bucket and report an overconsumption of
                // (remaining tokens / size) times larger than the bucket size
                tokens -= self.budget;
                self.budget = 0;
                return BucketReduction::OverConsumption(tokens as f64 / self.size as f64);
            }
            // If not enough tokens consume() fails, return false.
            return BucketReduction::Failure;
        }

        self.budget -= tokens;
        BucketReduction::Success
    }

    /// "Manually" adds tokens to bucket.
    pub fn replenish(&mut self, tokens: u64) {
        // This means we are still during the burst interval.
        // Of course there is a very small chance  that the last reduce() also used up burst
        // budget which should now be replenished, but for performance and code-complexity
        // reasons we're just gonna let that slide since it's practically inconsequential.
        if self.one_time_burst > 0 {
            self.one_time_burst += tokens;
            return;
        }
        self.budget = std::cmp::min(self.budget + tokens, self.size);
    }

    /// Returns the capacity of the token bucket.
    pub fn capacity(&self) -> u64 {
        self.size
    }

    /// Returns the remaining one time burst budget.
    pub fn one_time_burst(&self) -> u64 {
        self.one_time_burst
    }

    /// Returns the time in milliseconds required to to completely fill the bucket.
    pub fn refill_time_ms(&self) -> u64 {
        self.refill_time
    }

    /// Returns the current budget (one time burst allowance notwithstanding).
    pub fn budget(&self) -> u64 {
        self.budget
    }
}

/// Enum that describes the type of token used.
#[derive(Copy, Clone)]
pub enum TokenType {
    /// Token type used for bandwidth limiting.
    Bytes,
    /// Token type used for operations/second limiting.
    Ops,
}

/// Enum that describes the type of token bucket update.
pub enum BucketUpdate {
    /// No Update - same as before.
    None,
    /// Rate Limiting is disabled on this bucket.
    Disabled,
    /// Rate Limiting enabled with updated bucket.
    Update(TokenBucket),
}

/// Rate Limiter that works on both bandwidth and ops/s limiting.
///
/// Bandwidth (bytes/s) and ops/s limiting can be used at the same time or individually.
///
/// Implementation uses a single timer through TimerFd to refresh either or
/// both token buckets.
///
/// Its internal buckets are 'passively' replenished as they're being used (as
/// part of `consume()` operations).
/// A timer is enabled and used to 'actively' replenish the token buckets when
/// limiting is in effect and `consume()` operations are disabled.
///
/// RateLimiters will generate events on the FDs provided by their `AsRawFd` trait
/// implementation. These events are meant to be consumed by the user of this struct.
/// On each such event, the user must call the `event_handler()` method.
pub struct RateLimiter {
    inner: Mutex<RateLimiterInner>,

    // Internal flag that quickly determines timer state.
    timer_active: AtomicBool,
    managed_enabled: AtomicBool,
}

struct RateLimiterInner {
    bandwidth: Option<TokenBucket>,
    ops: Option<TokenBucket>,

    timer_fd: TimerFd,
    managed_retry: [Option<Instant>; 2],
}

impl RateLimiterInner {
    fn settle_managed(&mut self, now: Instant) {
        for bucket in [&mut self.bandwidth, &mut self.ops].into_iter().flatten() {
            bucket.settle_at(now);
        }
    }

    fn reschedule_managed(&mut self, now: Instant, flag: &AtomicBool) -> io::Result<()> {
        let mut delay = None;
        for (index, bucket) in [self.bandwidth.as_ref(), self.ops.as_ref()]
            .into_iter()
            .enumerate()
        {
            let Some(bucket) = bucket.filter(|bucket| bucket.enabled) else {
                self.managed_retry[index] = None;
                continue;
            };
            if let Some(debt) = bucket.debt_delay() {
                delay = Some(delay.map_or(debt, |old: Duration| old.max(debt)));
            }
            if let Some(retry) = self.managed_retry[index] {
                if retry > now {
                    let retry = retry.duration_since(now);
                    delay = Some(delay.map_or(retry, |old| old.max(retry)));
                } else {
                    self.managed_retry[index] = None;
                }
            }
        }
        // Only the timer driver may retire an existing block. A late completed
        // transfer or rollback must leave readiness for sleeping peer queues.
        if delay.is_none() {
            if !flag.load(Ordering::Acquire) {
                return Ok(());
            }
            delay = Some(Duration::from_nanos(1));
        }
        self.timer_fd.reset(delay.unwrap_or(Duration::ZERO), None)?;
        flag.store(delay.is_some(), Ordering::Release);
        Ok(())
    }

    // Arm the timer of the rate limiter with the provided `Duration` (which will fire only once).
    fn activate_timer(&mut self, dur: Duration, flag: &AtomicBool) {
        // Panic when failing to arm the timer (same handling in crate TimerFd::set_state())
        self.timer_fd
            .reset(dur, None)
            .expect("Can't arm the timer (unexpected 'timerfd_settime' failure).");
        flag.store(true, Ordering::Relaxed);
    }
}

impl RateLimiter {
    /// Creates a new Rate Limiter that can limit on both bytes/s and ops/s.
    ///
    /// # Arguments
    ///
    /// * `bytes_total_capacity` - the total capacity of the `TokenType::Bytes` token bucket.
    /// * `bytes_one_time_burst` - initial extra credit on top of `bytes_total_capacity`,
    ///   that does not replenish and which can be used for an initial burst of data.
    /// * `bytes_complete_refill_time_ms` - number of milliseconds for the `TokenType::Bytes`
    ///   token bucket to go from zero Bytes to `bytes_total_capacity` Bytes.
    /// * `ops_total_capacity` - the total capacity of the `TokenType::Ops` token bucket.
    /// * `ops_one_time_burst` - initial extra credit on top of `ops_total_capacity`,
    ///   that does not replenish and which can be used for an initial burst of data.
    /// * `ops_complete_refill_time_ms` - number of milliseconds for the `TokenType::Ops` token
    ///   bucket to go from zero Ops to `ops_total_capacity` Ops.
    ///
    /// If either bytes/ops *size* or *refill_time* are **zero**, the limiter
    /// is **disabled** for that respective token type.
    ///
    /// # Errors
    ///
    /// If the timerfd creation fails, an error is returned.
    pub fn new(
        bytes_total_capacity: u64,
        bytes_one_time_burst: u64,
        bytes_complete_refill_time_ms: u64,
        ops_total_capacity: u64,
        ops_one_time_burst: u64,
        ops_complete_refill_time_ms: u64,
    ) -> io::Result<Self> {
        for (size, refill_time) in [
            (bytes_total_capacity, bytes_complete_refill_time_ms),
            (ops_total_capacity, ops_complete_refill_time_ms),
        ] {
            if size != 0 && refill_time > u64::MAX / NANOSEC_IN_ONE_MILLISEC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bucket refill overflows nanoseconds",
                ));
            }
        }
        let bytes_token_bucket = TokenBucket::new(
            bytes_total_capacity,
            bytes_one_time_burst,
            bytes_complete_refill_time_ms,
        );

        let ops_token_bucket = TokenBucket::new(
            ops_total_capacity,
            ops_one_time_burst,
            ops_complete_refill_time_ms,
        );

        // We'll need a timer_fd, even if our current config effectively disables rate limiting,
        // because `Self::update_buckets()` might re-enable it later, and we might be
        // seccomp-blocked from creating the timer_fd at that time.
        let timer_fd = TimerFd::new()?;
        // Note: vmm_sys_util::TimerFd::new() open the fd w/o O_NONBLOCK. We manually add this flag
        // so that `Self::event_handler` won't be blocked with `vmm_sys_util::TimerFd::wait()`.
        // SAFETY: FFI calls.
        let ret = unsafe {
            let fd = timer_fd.as_raw_fd();
            let mut flags = libc::fcntl(fd, libc::F_GETFL);
            flags |= libc::O_NONBLOCK;
            libc::fcntl(fd, libc::F_SETFL, flags)
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(RateLimiter {
            inner: Mutex::new(RateLimiterInner {
                bandwidth: bytes_token_bucket,
                ops: ops_token_bucket,
                timer_fd,
                managed_retry: [None, None],
            }),
            timer_active: AtomicBool::new(false),
            managed_enabled: AtomicBool::new(
                (bytes_total_capacity != 0 && bytes_complete_refill_time_ms != 0)
                    || (ops_total_capacity != 0 && ops_complete_refill_time_ms != 0),
            ),
        })
    }

    /// Observe actual effective policy, credit and debt without changing them.
    pub fn managed_state(&self) -> RateLimiterState {
        let inner = self.inner.lock().unwrap();
        RateLimiterState {
            bandwidth: inner
                .bandwidth
                .as_ref()
                .map_or(BucketState::default(), TokenBucket::state),
            ops: inner
                .ops
                .as_ref()
                .map_or(BucketState::default(), TokenBucket::state),
            blocked: self.timer_active.load(Ordering::Acquire),
        }
    }

    /// Change bandwidth without refilling credit, renewing burst or erasing debt.
    /// None explicitly disables bandwidth; operation limits are unchanged.
    pub fn update_bandwidth(&self, target: Option<BucketConfig>) -> io::Result<bool> {
        if let Some(config) = target {
            config.validate()?;
        }
        let mut inner = self.inner.lock().unwrap();
        let current = inner.bandwidth.as_ref().and_then(TokenBucket::configured);
        if current == target {
            return Ok(false);
        }
        let now = Instant::now();
        inner.settle_managed(now);
        match (inner.bandwidth.as_mut(), target) {
            (Some(bucket), Some(config)) => {
                let was_enabled = bucket.enabled;
                bucket.size = config.size;
                bucket.refill_time = config.refill_time;
                bucket.configured_burst = config.one_time_burst;
                bucket.one_time_burst = if was_enabled {
                    bucket.one_time_burst.min(config.one_time_burst)
                } else {
                    0
                };
                bucket.budget = bucket.budget.min(config.size);
                if bucket.budget == config.size {
                    bucket.fraction = 0;
                }
                bucket.enabled = true;
                let refill_ns = config.refill_time * NANOSEC_IN_ONE_MILLISEC;
                let factor = gcd(config.size, refill_ns);
                bucket.processed_capacity = config.size / factor;
                bucket.processed_refill_time = refill_ns / factor;
            }
            (Some(bucket), None) => {
                bucket.enabled = false;
                bucket.budget = 0;
                bucket.fraction = 0;
                bucket.one_time_burst = 0;
            }
            (None, Some(config)) => {
                inner.bandwidth =
                    TokenBucket::new(config.size, config.one_time_burst, config.refill_time);
            }
            (None, None) => unreachable!(),
        }
        inner.managed_retry[0] = None;
        self.managed_enabled.store(
            inner
                .bandwidth
                .as_ref()
                .is_some_and(|bucket| bucket.enabled)
                || inner.ops.as_ref().is_some_and(|bucket| bucket.enabled),
            Ordering::Release,
        );
        // Drain old readiness while the same lock excludes the timer handler.
        inner.timer_fd.reset(Duration::ZERO, None)?;
        loop {
            match inner.timer_fd.wait().map_err(io::Error::from) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        self.timer_active.store(false, Ordering::Release);
        inner.reschedule_managed(now, &self.timer_active)?;
        Ok(true)
    }

    /// Admit block-style work before I/O, borrowing only for oversized requests.
    pub fn consume_managed(&self, tokens: u64, token_type: TokenType) -> bool {
        if !self.managed_enabled.load(Ordering::Acquire) {
            return true;
        }
        if self.is_blocked() {
            return false;
        }
        let mut inner = self.inner.lock().unwrap();
        if self.is_blocked() {
            return false;
        }
        let now = Instant::now();
        inner.settle_managed(now);
        let index = match token_type {
            TokenType::Bytes => 0,
            TokenType::Ops => 1,
        };
        let bucket = match token_type {
            TokenType::Bytes => &mut inner.bandwidth,
            TokenType::Ops => &mut inner.ops,
        };
        let mut admitted = true;
        if let Some(bucket) = bucket.as_mut().filter(|bucket| bucket.enabled) {
            let remaining = tokens.saturating_sub(bucket.one_time_burst);
            let available = u128::from(bucket.budget) * TOKEN_SCALE + bucket.fraction;
            if u128::from(remaining) * TOKEN_SCALE > available && remaining <= bucket.size {
                admitted = false;
            } else {
                bucket.charge(tokens);
            }
        }
        if !admitted {
            inner.managed_retry[index] = Some(now + TIMER_REFILL_DUR);
        }
        inner
            .reschedule_managed(now, &self.timer_active)
            .expect("cannot arm group limiter timer");
        admitted
    }

    /// Charge both actual completed-I/O axes, even after another consumer blocks.
    /// False means consumers must wait; the transferred work is always charged.
    pub fn account_transferred(&self, bytes: u64, ops: u64) -> io::Result<bool> {
        if !self.managed_enabled.load(Ordering::Acquire) {
            return Ok(true);
        }
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        inner.settle_managed(now);
        if let Some(bucket) = &mut inner.bandwidth {
            bucket.charge(bytes);
        }
        if let Some(bucket) = &mut inner.ops {
            bucket.charge(ops);
        }
        inner.reschedule_managed(now, &self.timer_active)?;
        Ok(!self.is_blocked())
    }

    /// Roll back pre-admitted work, paying outstanding debt before adding credit.
    pub fn manual_replenish_managed(&self, tokens: u64, token_type: TokenType) {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        inner.settle_managed(now);
        let bucket = match token_type {
            TokenType::Bytes => &mut inner.bandwidth,
            TokenType::Ops => &mut inner.ops,
        };
        if let Some(bucket) = bucket.as_mut().filter(|bucket| bucket.enabled) {
            let credit = u128::from(tokens) * TOKEN_SCALE;
            let repaid = credit.min(bucket.debt);
            bucket.debt -= repaid;
            let remaining = (credit - repaid) / TOKEN_SCALE;
            if bucket.one_time_burst != 0 {
                bucket.one_time_burst =
                    u64::try_from(u128::from(bucket.one_time_burst) + remaining)
                        .unwrap_or(u64::MAX)
                        .min(bucket.configured_burst);
            } else {
                bucket.budget = u64::try_from(u128::from(bucket.budget) + remaining)
                    .unwrap_or(u64::MAX)
                    .min(bucket.size);
            }
        }
        inner
            .reschedule_managed(now, &self.timer_active)
            .expect("cannot arm group limiter timer");
    }

    /// Drain group timer readiness; stale events are benign, and unpaid debt stays blocked.
    pub fn managed_event_handler(&self) -> io::Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        loop {
            match inner.timer_fd.wait().map_err(io::Error::from) {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        let now = Instant::now();
        self.timer_active.store(false, Ordering::Release);
        inner.settle_managed(now);
        inner.reschedule_managed(now, &self.timer_active)?;
        Ok(!self.is_blocked())
    }

    /// Attempts to consume tokens and returns whether that is possible.
    ///
    /// If rate limiting is disabled on provided `token_type`, this function will always succeed.
    pub fn consume(&self, tokens: u64, token_type: TokenType) -> bool {
        // If the timer is active, we can't consume tokens from any bucket and the function fails.
        if self.is_blocked() {
            return false;
        }
        let mut guard = self.inner.lock().unwrap();
        // Identify the required token bucket.
        let token_bucket = match token_type {
            TokenType::Bytes => guard.bandwidth.as_mut(),
            TokenType::Ops => guard.ops.as_mut(),
        };
        // Try to consume from the token bucket.
        if let Some(bucket) = token_bucket {
            let refill_time = bucket.refill_time_ms();
            match bucket.reduce(tokens) {
                // When we report budget is over, there will be no further calls here,
                // register a timer to replenish the bucket and resume processing;
                // make sure there is only one running timer for this limiter.
                BucketReduction::Failure => {
                    if !self.is_blocked() {
                        guard.activate_timer(TIMER_REFILL_DUR, &self.timer_active);
                    }
                    false
                }
                // The operation succeeded and further calls can be made.
                BucketReduction::Success => true,
                // The operation succeeded as the tokens have been consumed
                // but the timer still needs to be armed.
                BucketReduction::OverConsumption(ratio) => {
                    // The operation "borrowed" a number of tokens `ratio` times
                    // greater than the size of the bucket, and since it takes
                    // `refill_time` milliseconds to fill an empty bucket, in
                    // order to enforce the bandwidth limit we need to prevent
                    // further calls to the rate limiter for
                    // `ratio * refill_time` milliseconds.
                    guard.activate_timer(
                        Duration::from_millis((ratio * refill_time as f64) as u64),
                        &self.timer_active,
                    );
                    true
                }
            }
        } else {
            // If bucket is not present rate limiting is disabled on token type,
            // consume() will always succeed.
            true
        }
    }

    /// Adds tokens of `token_type` to their respective bucket.
    ///
    /// Can be used to *manually* add tokens to a bucket. Useful for reverting a
    /// `consume()` if needed.
    pub fn manual_replenish(&self, tokens: u64, token_type: TokenType) {
        let mut guard = self.inner.lock().unwrap();
        // Identify the required token bucket.
        let token_bucket = match token_type {
            TokenType::Bytes => guard.bandwidth.as_mut(),
            TokenType::Ops => guard.ops.as_mut(),
        };
        // Add tokens to the token bucket.
        if let Some(bucket) = token_bucket {
            bucket.replenish(tokens);
        }
    }

    /// Returns whether this rate limiter is blocked.
    ///
    /// The limiter 'blocks' when a `consume()` operation fails because there was not enough
    /// budget for it.
    /// An event will be generated on the exported FD when the limiter 'unblocks'.
    pub fn is_blocked(&self) -> bool {
        self.timer_active.load(Ordering::Relaxed)
    }

    /// This function needs to be called every time there is an event on the
    /// FD provided by this object's `AsRawFd` trait implementation.
    ///
    /// # Errors
    ///
    /// If the rate limiter is disabled or is not blocked, an error is returned.
    pub fn event_handler(&self) -> Result<(), Error> {
        let mut guard = self.inner.lock().unwrap();
        loop {
            // Note: As we manually added the `O_NONBLOCK` flag to the FD, the following
            // `timer_fd::wait()` won't block (which is different from its default behavior.)
            match guard.timer_fd.wait() {
                Err(e) => {
                    let err: std::io::Error = e.into();
                    match err.kind() {
                        std::io::ErrorKind::Interrupted => (),
                        std::io::ErrorKind::WouldBlock => {
                            return Err(Error::SpuriousRateLimiterEvent(
                                "Rate limiter event handler called without a present timer",
                            ));
                        }
                        _ => return Err(Error::TimerFdWaitError(err)),
                    }
                }
                _ => {
                    self.timer_active.store(false, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }
    }

    /// Updates the parameters of the token buckets associated with this RateLimiter.
    // TODO: Please note that, right now, the buckets become full after being updated.
    pub fn update_buckets(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        let guard = self.inner.get_mut().unwrap();
        match bytes {
            BucketUpdate::Disabled => guard.bandwidth = None,
            BucketUpdate::Update(tb) => guard.bandwidth = Some(tb),
            BucketUpdate::None => (),
        }
        match ops {
            BucketUpdate::Disabled => guard.ops = None,
            BucketUpdate::Update(tb) => guard.ops = Some(tb),
            BucketUpdate::None => (),
        }
    }
}

impl AsRawFd for RateLimiter {
    /// Provides a FD which needs to be monitored for POLLIN events.
    ///
    /// This object's `event_handler()` method must be called on such events.
    ///
    /// Will return a negative value if rate limiting is disabled on both
    /// token types.
    fn as_raw_fd(&self) -> RawFd {
        let guard = self.inner.lock().unwrap();
        guard.timer_fd.as_raw_fd()
    }
}

impl Default for RateLimiter {
    /// Default RateLimiter is a no-op limiter with infinite budget.
    fn default() -> Self {
        // Safe to unwrap since this will not attempt to create timer_fd.
        RateLimiter::new(0, 0, 0, 0, 0, 0).expect("Failed to build default RateLimiter")
    }
}

#[cfg(test)]
pub(crate) mod unit_tests {
    use std::{fmt, thread};

    use super::*;

    impl TokenBucket {
        // Resets the token bucket: budget set to max capacity and last-updated set to now.
        fn reset(&mut self) {
            self.budget = self.size;
            self.last_update = Instant::now();
        }

        fn get_last_update(&self) -> &Instant {
            &self.last_update
        }

        fn get_processed_capacity(&self) -> u64 {
            self.processed_capacity
        }

        fn get_processed_refill_time(&self) -> u64 {
            self.processed_refill_time
        }

        // After a restore, we cannot be certain that the last_update field has the same value.
        #[allow(dead_code)]
        fn partial_eq(&self, other: &TokenBucket) -> bool {
            (other.capacity() == self.capacity())
                && (other.one_time_burst() == self.one_time_burst())
                && (other.refill_time_ms() == self.refill_time_ms())
                && (other.budget() == self.budget())
        }
    }

    impl RateLimiter {
        fn bandwidth(&self) -> Option<TokenBucket> {
            let guard = self.inner.lock().unwrap();
            guard.bandwidth.clone()
        }

        fn ops(&self) -> Option<TokenBucket> {
            let guard = self.inner.lock().unwrap();
            guard.ops.clone()
        }
    }

    impl PartialEq for RateLimiter {
        fn eq(&self, other: &RateLimiter) -> bool {
            let self_guard = self.inner.lock().unwrap();
            let other_guard = other.inner.lock().unwrap();
            self_guard.bandwidth == other_guard.bandwidth && self_guard.ops == other_guard.ops
        }
    }

    impl fmt::Debug for RateLimiter {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let guard = self.inner.lock().unwrap();
            write!(
                f,
                "RateLimiter {{ bandwidth: {:?}, ops: {:?} }}",
                guard.bandwidth, guard.ops
            )
        }
    }

    #[test]
    fn test_token_bucket_create() {
        let before = Instant::now();
        let tb = TokenBucket::new(1000, 0, 1000).unwrap();
        assert_eq!(tb.capacity(), 1000);
        assert_eq!(tb.budget(), 1000);
        assert!(*tb.get_last_update() >= before);
        let after = Instant::now();
        assert!(*tb.get_last_update() <= after);
        assert_eq!(tb.get_processed_capacity(), 1);
        assert_eq!(tb.get_processed_refill_time(), 1_000_000);

        // Verify invalid bucket configurations result in `None`.
        assert!(TokenBucket::new(0, 1234, 1000).is_none());
        assert!(TokenBucket::new(100, 1234, 0).is_none());
        assert!(TokenBucket::new(0, 1234, 0).is_none());
    }

    #[test]
    fn test_token_bucket_preprocess() {
        let tb = TokenBucket::new(1000, 0, 1000).unwrap();
        assert_eq!(tb.get_processed_capacity(), 1);
        assert_eq!(tb.get_processed_refill_time(), NANOSEC_IN_ONE_MILLISEC);

        let thousand = 1000;
        let tb = TokenBucket::new(3 * 7 * 11 * 19 * thousand, 0, 7 * 11 * 13 * 17).unwrap();
        assert_eq!(tb.get_processed_capacity(), 3 * 19);
        assert_eq!(
            tb.get_processed_refill_time(),
            13 * 17 * (NANOSEC_IN_ONE_MILLISEC / thousand)
        );
    }

    #[test]
    fn test_token_bucket_reduce() {
        // token bucket with capacity 1000 and refill time of 1000 milliseconds
        // allowing rate of 1 token/ms.
        let capacity = 1000;
        let refill_ms = 1000;
        let mut tb = TokenBucket::new(capacity, 0, refill_ms as u64).unwrap();

        assert_eq!(tb.reduce(123), BucketReduction::Success);
        assert_eq!(tb.budget(), capacity - 123);

        thread::sleep(Duration::from_millis(123));
        assert_eq!(tb.reduce(1), BucketReduction::Success);
        assert_eq!(tb.budget(), capacity - 1);
        assert_eq!(tb.reduce(100), BucketReduction::Success);
        assert_eq!(tb.reduce(capacity), BucketReduction::Failure);

        // token bucket with capacity 1000 and refill time of 1000 milliseconds
        let mut tb = TokenBucket::new(1000, 1100, 1000).unwrap();
        // safely assuming the thread can run these 3 commands in less than 500ms
        assert_eq!(tb.reduce(1000), BucketReduction::Success);
        assert_eq!(tb.one_time_burst(), 100);
        assert_eq!(tb.reduce(500), BucketReduction::Success);
        assert_eq!(tb.one_time_burst(), 0);
        assert_eq!(tb.reduce(500), BucketReduction::Success);
        assert_eq!(tb.reduce(500), BucketReduction::Failure);
        thread::sleep(Duration::from_millis(500));
        assert_eq!(tb.reduce(500), BucketReduction::Success);
        thread::sleep(Duration::from_millis(1000));
        assert_eq!(tb.reduce(2500), BucketReduction::OverConsumption(1.5));

        let before = Instant::now();
        tb.reset();
        assert_eq!(tb.capacity(), 1000);
        assert_eq!(tb.budget(), 1000);
        assert!(*tb.get_last_update() >= before);
        let after = Instant::now();
        assert!(*tb.get_last_update() <= after);
    }

    #[test]
    fn test_rate_limiter_default() {
        let l = RateLimiter::default();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::MAX, TokenType::Ops));
        assert!(l.consume(u64::MAX, TokenType::Bytes));
        // calling the handler without there having been an event should error
        l.event_handler().unwrap_err();
        assert_eq!(
            format!("{:?}", l.event_handler().err().unwrap()),
            "SpuriousRateLimiterEvent(\
             \"Rate limiter event handler called without a present timer\")"
        );
    }

    #[test]
    fn test_rate_limiter_new() {
        let l = RateLimiter::new(1000, 1001, 1002, 1003, 1004, 1005).unwrap();
        let bw = l.bandwidth().unwrap();
        assert_eq!(bw.capacity(), 1000);
        assert_eq!(bw.one_time_burst(), 1001);
        assert_eq!(bw.refill_time_ms(), 1002);
        assert_eq!(bw.budget(), 1000);

        let ops = l.ops().unwrap();
        assert_eq!(ops.capacity(), 1003);
        assert_eq!(ops.one_time_burst(), 1004);
        assert_eq!(ops.refill_time_ms(), 1005);
        assert_eq!(ops.budget(), 1003);
    }

    #[test]
    fn test_rate_limiter_manual_replenish() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let l = RateLimiter::new(1000, 0, 1000, 1000, 0, 1000).unwrap();

        // consume 123 bytes
        assert!(l.consume(123, TokenType::Bytes));
        l.manual_replenish(23, TokenType::Bytes);
        {
            let bytes_tb = l.bandwidth().unwrap();
            assert_eq!(bytes_tb.budget(), 900);
        }
        // consume 123 ops
        assert!(l.consume(123, TokenType::Ops));
        l.manual_replenish(23, TokenType::Ops);
        {
            let bytes_tb = l.ops().unwrap();
            assert_eq!(bytes_tb.budget(), 900);
        }
    }

    #[test]
    fn test_rate_limiter_bandwidth() {
        // rate limiter with limit of 1000 bytes/s
        let l = RateLimiter::new(1000, 0, 1000, 0, 0, 0).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // ops/s limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::MAX, TokenType::Ops));

        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Bytes));
        // try and fail on another 100
        assert!(!l.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        l.event_handler().unwrap();
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 bytes this time
        assert!(l.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_ops() {
        // rate limiter with limit of 1000 ops/s
        let l = RateLimiter::new(0, 0, 0, 1000, 0, 1000).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // bytes/s limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::MAX, TokenType::Bytes));

        // do full 1000 ops
        assert!(l.consume(1000, TokenType::Ops));
        // try and fail on another 100
        assert!(!l.consume(100, TokenType::Ops));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        l.event_handler().unwrap();
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(l.consume(100, TokenType::Ops));
    }

    #[test]
    fn test_rate_limiter_full() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let l = RateLimiter::new(1000, 0, 1000, 1000, 0, 1000).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Ops));
        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Bytes));
        // try and fail on another 100 ops
        assert!(!l.consume(100, TokenType::Ops));
        // try and fail on another 100 bytes
        assert!(!l.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        l.event_handler().unwrap();
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(l.consume(100, TokenType::Ops));
        // try and succeed on another 100 bytes this time
        assert!(l.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_overconsumption() {
        // initialize the rate limiter
        let l = RateLimiter::new(1000, 0, 1000, 1000, 0, 1000).unwrap();
        // try to consume 2.5x the bucket size
        // we are "borrowing" 1.5x the bucket size in tokens since
        // the bucket is full
        assert!(l.consume(2500, TokenType::Bytes));

        // check that even after a whole second passes, the rate limiter
        // is still blocked
        thread::sleep(Duration::from_millis(1000));
        l.event_handler().unwrap_err();
        assert!(l.is_blocked());

        // after 1.5x the replenish time has passed, the rate limiter
        // is available again
        thread::sleep(Duration::from_millis(500));
        l.event_handler().unwrap();
        assert!(!l.is_blocked());

        // reset the rate limiter
        let l = RateLimiter::new(1000, 0, 1000, 1000, 0, 1000).unwrap();
        // try to consume 1.5x the bucket size
        // we are "borrowing" 1.5x the bucket size in tokens since
        // the bucket is full, should arm the timer to 0.5x replenish
        // time, which is 500 ms
        assert!(l.consume(1500, TokenType::Bytes));

        // check that after more than the minimum refill time,
        // the rate limiter is still blocked
        thread::sleep(Duration::from_millis(200));
        l.event_handler().unwrap_err();
        assert!(l.is_blocked());

        // try to consume some tokens, which should fail as the timer
        // is still active
        assert!(!l.consume(100, TokenType::Bytes));
        l.event_handler().unwrap_err();
        assert!(l.is_blocked());

        // check that after the minimum refill time, the timer was not
        // overwritten and the rate limiter is still blocked from the
        // borrowing we performed earlier
        thread::sleep(Duration::from_millis(100));
        l.event_handler().unwrap_err();
        assert!(l.is_blocked());
        assert!(!l.consume(100, TokenType::Bytes));

        // after waiting out the full duration, rate limiter should be
        // available again
        thread::sleep(Duration::from_millis(200));
        l.event_handler().unwrap();
        assert!(!l.is_blocked());
        assert!(l.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_update_buckets() {
        let mut x = RateLimiter::new(1000, 2000, 1000, 10, 20, 1000).unwrap();

        let initial_bw = x.bandwidth();
        let initial_ops = x.ops();

        x.update_buckets(BucketUpdate::None, BucketUpdate::None);
        assert_eq!(x.bandwidth(), initial_bw);
        assert_eq!(x.ops(), initial_ops);

        let new_bw = TokenBucket::new(123, 0, 57).unwrap();
        let new_ops = TokenBucket::new(321, 12346, 89).unwrap();
        x.update_buckets(
            BucketUpdate::Update(new_bw.clone()),
            BucketUpdate::Update(new_ops.clone()),
        );

        {
            let mut guard = x.inner.lock().unwrap();
            // We have manually adjust the last_update field, because it changes when update_buckets()
            // constructs new buckets (and thus gets a different value for last_update). We do this so
            // it makes sense to test the following assertions.
            guard.bandwidth.as_mut().unwrap().last_update = new_bw.last_update;
            guard.ops.as_mut().unwrap().last_update = new_ops.last_update;
        }

        assert_eq!(x.bandwidth(), Some(new_bw));
        assert_eq!(x.ops(), Some(new_ops));

        x.update_buckets(BucketUpdate::Disabled, BucketUpdate::Disabled);
        assert_eq!(x.bandwidth(), None);
        assert_eq!(x.ops(), None);
    }

    #[test]
    fn test_rate_limiter_debug() {
        let l = RateLimiter::new(1, 2, 3, 4, 5, 6).unwrap();
        assert_eq!(
            format!("{l:?}"),
            format!(
                "RateLimiter {{ bandwidth: {:?}, ops: {:?} }}",
                l.bandwidth(),
                l.ops()
            ),
        );
    }

    fn live_config(size: u64, burst: u64) -> BucketConfig {
        BucketConfig {
            size,
            one_time_burst: burst,
            refill_time: 1_000_000,
        }
    }

    #[test]
    fn live_same_target_preserves_consumed_credit_and_block() {
        let limiter = RateLimiter::new(100, 1000, 1_000_000, 0, 0, 0).unwrap();
        assert!(limiter.consume_managed(1101, TokenType::Bytes));
        let before = limiter.managed_state();
        let bucket = limiter.inner.lock().unwrap().bandwidth.clone();
        assert!(before.blocked);
        assert_eq!(before.bandwidth.debt, 1);
        for _ in 0..20 {
            assert!(
                !limiter
                    .update_bandwidth(Some(live_config(100, 1000)))
                    .unwrap()
            );
        }
        assert_eq!(limiter.managed_state(), before);
        assert_eq!(limiter.inner.lock().unwrap().bandwidth, bucket);
    }

    #[test]
    fn live_completed_packets_charge_bytes_and_ops_even_while_blocked() {
        let limiter = RateLimiter::new(100, 0, 1_000_000, 1, 0, 1_000_000).unwrap();
        limiter.account_transferred(200, 2).unwrap();
        assert!(limiter.is_blocked());
        limiter.account_transferred(200, 2).unwrap();
        let state = limiter.managed_state();
        assert_eq!(state.bandwidth.debt, 300);
        assert_eq!(state.ops.debt, 3);
        assert_eq!(state.bandwidth.budget, 0);
    }

    #[test]
    fn live_real_rate_changes_do_not_erase_debt_or_renew_burst() {
        let limiter = RateLimiter::new(100, 1000, 1_000_000, 0, 0, 0).unwrap();
        limiter.account_transferred(1200, 1).unwrap();
        for size in [200, 50, 300, 100] {
            assert!(
                limiter
                    .update_bandwidth(Some(live_config(size, size * 10)))
                    .unwrap()
            );
            let state = limiter.managed_state();
            assert_eq!(state.bandwidth.burst, 0);
            assert_eq!(state.bandwidth.budget, 0);
            assert_eq!(state.bandwidth.debt, 100);
            assert!(state.blocked);
        }
    }

    #[test]
    fn live_disable_reenable_retains_debt_without_another_initial_burst() {
        let limiter = RateLimiter::new(100, 1000, 1_000_000, 0, 0, 0).unwrap();
        limiter.account_transferred(1200, 1).unwrap();
        assert!(limiter.update_bandwidth(None).unwrap());
        assert!(!limiter.is_blocked());
        assert_eq!(limiter.managed_state().bandwidth.configured, None);
        assert!(
            limiter
                .update_bandwidth(Some(live_config(200, 2000)))
                .unwrap()
        );
        let state = limiter.managed_state();
        assert_eq!(state.bandwidth.burst, 0);
        assert_eq!(state.bandwidth.debt, 100);
        assert!(state.blocked);
    }

    #[test]
    fn live_first_finite_policy_gets_one_initial_burst() {
        let limiter = RateLimiter::default();
        assert!(!limiter.update_bandwidth(None).unwrap());
        assert!(
            limiter
                .update_bandwidth(Some(live_config(100, 1000)))
                .unwrap()
        );
        assert_eq!(limiter.managed_state().bandwidth.burst, 1000);
        assert!(limiter.update_bandwidth(None).unwrap());
        assert!(
            limiter
                .update_bandwidth(Some(live_config(100, 1000)))
                .unwrap()
        );
        assert_eq!(limiter.managed_state().bandwidth.burst, 0);
    }

    #[test]
    fn live_bandwidth_change_preserves_an_ops_induced_block() {
        let limiter = RateLimiter::new(100, 0, 1_000_000, 1, 0, 1_000_000).unwrap();
        limiter.account_transferred(0, 10).unwrap();
        assert!(limiter.update_bandwidth(None).unwrap());
        let state = limiter.managed_state();
        assert_eq!(state.ops.debt, 9);
        assert!(state.blocked);
    }

    #[test]
    fn live_invalid_finite_policy_does_not_mutate_either_bucket() {
        let limiter = RateLimiter::new(100, 0, 1000, 1, 0, 1000).unwrap();
        let before = limiter.managed_state();
        for config in [
            BucketConfig {
                size: 0,
                one_time_burst: 0,
                refill_time: 1000,
            },
            BucketConfig {
                size: 1,
                one_time_burst: 0,
                refill_time: 0,
            },
            BucketConfig {
                size: 1,
                one_time_burst: 0,
                refill_time: u64::MAX,
            },
        ] {
            assert!(limiter.update_bandwidth(Some(config)).is_err());
            assert_eq!(limiter.managed_state(), before);
        }
    }

    #[test]
    fn live_elapsed_repayment_is_translated_before_a_rate_change() {
        let mut bucket = TokenBucket::new(100, 0, 1000).unwrap();
        let start = bucket.last_update;
        bucket.budget = 0;
        bucket.debt = 200 * TOKEN_SCALE;
        bucket.settle_at(start + Duration::from_secs(1));
        assert_eq!(bucket.debt, 100 * TOKEN_SCALE);
        bucket.size = 200;
        bucket.settle_at(start + Duration::from_millis(1500));
        assert_eq!(bucket.debt, 0);
        assert_eq!(bucket.budget, 0);
        bucket.settle_at(start + Duration::from_secs(2));
        assert_eq!(bucket.budget, 100);
    }

    #[test]
    fn live_stale_timer_readiness_is_benign_without_changing_local_behavior() {
        let limiter = RateLimiter::default();
        assert!(!limiter.managed_event_handler().unwrap());
        assert!(limiter.event_handler().is_err());
    }
}
