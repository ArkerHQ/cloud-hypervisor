// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2023 Crusoe Energy Systems LLC
// SPDX-License-Identifier: Apache-2.0

use core::panic::AssertUnwindSafe;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::{io, result, thread};

use log::{error, info, warn};
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

use crate::{BucketConfig, RateLimiter, RateLimiterState, TokenType};

/// Errors associated with rate-limiter group.
#[derive(Debug, Error)]
pub enum Error {
    /// Cannot create thread
    #[error("Error spawning rate-limiter thread {0}")]
    ThreadSpawn(#[source] io::Error),

    /// Cannot create epoll context.
    #[error("Error creating epoll context")]
    Epoll(#[source] io::Error),

    /// Cannot create EventFd.
    #[error("Error creating EventFd")]
    EventFd(#[source] io::Error),

    /// Cannot create RateLimiter.
    #[error("Error creating RateLimiter")]
    RateLimiter(#[source] io::Error),

    /// Cannot read from EventFd.
    #[error("Error reading from EventFd")]
    EventFdRead(#[source] io::Error),

    /// Cannot write to EventFd.
    #[error("Error writing to EventFd")]
    EventFdWrite(#[source] io::Error),
}

/// Handle to a RateLimiterGroup
///
/// The RateLimiterGroupHandle may be used in exactly the same way as
/// the RateLimiter type. When the RateLimiter within a RateLimiterGroup
/// is unblocked, each RateLimiterGroupHandle will be notified.
pub struct RateLimiterGroupHandle {
    eventfd: Arc<EventFd>,
    inner: Arc<RateLimiterGroupInner>,
}

impl RateLimiterGroupHandle {
    fn new(inner: Arc<RateLimiterGroupInner>) -> result::Result<Self, Error> {
        let eventfd =
            Arc::new(EventFd::new(libc::EFD_NONBLOCK | libc::EFD_CLOEXEC).map_err(Error::EventFd)?);
        inner.handles.lock().unwrap().push(eventfd.clone());
        Ok(Self { eventfd, inner })
    }

    /// Attempts to consume tokens and returns whether that is possible.
    ///
    /// If rate limiting is disabled on provided `token_type`, this function will always succeed.
    pub fn consume(&self, tokens: u64, token_type: TokenType) -> bool {
        self.inner.rate_limiter.consume_managed(tokens, token_type)
    }

    /// Charge both completed-I/O axes, including transfers racing a blocked peer.
    pub fn account_transferred(&self, bytes: u64, ops: u64) -> result::Result<bool, Error> {
        self.inner
            .rate_limiter
            .account_transferred(bytes, ops)
            .map_err(Error::RateLimiter)
    }

    /// Adds tokens of `token_type` to their respective bucket.
    ///
    /// Can be used to *manually* add tokens to a bucket. Useful for reverting a
    /// `consume()` if needed.
    pub fn manual_replenish(&self, tokens: u64, token_type: TokenType) {
        self.inner
            .rate_limiter
            .manual_replenish_managed(tokens, token_type);
    }

    /// This function needs to be called every time there is an event on the
    /// FD provided by this object's `AsRawFd` trait implementation.
    ///
    /// # Errors
    ///
    /// Stale nonblocking readiness is benign.
    pub fn event_handler(&self) -> Result<(), Error> {
        match self.eventfd.read() {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(Error::EventFdRead(error)),
        }
    }

    /// Returns whether this rate limiter is blocked.
    ///
    /// The limiter 'blocks' when a `consume()` operation fails because there was not enough
    /// budget for it.
    /// An event will be generated on the exported FD when the limiter 'unblocks'.
    pub fn is_blocked(&self) -> bool {
        self.inner.rate_limiter.is_blocked()
    }
}

impl Clone for RateLimiterGroupHandle {
    fn clone(&self) -> Self {
        RateLimiterGroupHandle::new(self.inner.clone()).unwrap()
    }
}

impl AsRawFd for RateLimiterGroupHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }
}

impl Drop for RateLimiterGroupHandle {
    fn drop(&mut self) {
        let mut handles = self.inner.handles.lock().unwrap();
        let index = handles
            .iter()
            .position(|handle| handle.as_raw_fd() == self.eventfd.as_raw_fd())
            .expect("RateLimiterGroupHandle must be subscribed to RateLimiterGroup");
        handles.remove(index);
    }
}

struct RateLimiterGroupInner {
    id: String,
    rate_limiter: RateLimiter,
    handles: Mutex<Vec<Arc<EventFd>>>,
}

impl RateLimiterGroupInner {
    fn notify(&self) -> result::Result<(), Error> {
        for handle in self.handles.lock().unwrap().iter() {
            loop {
                match handle.write(1) {
                    Ok(()) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(Error::EventFdWrite(error)),
                }
            }
        }
        Ok(())
    }

    fn process_timer(&self) -> result::Result<(), Error> {
        if self
            .rate_limiter
            .managed_event_handler()
            .map_err(Error::RateLimiter)?
        {
            self.notify()?;
        }
        Ok(())
    }
}

/// A RateLimiterGroup is an extension of RateLimiter that enables rate-limiting
/// the aggregate io consumption of multiple consumers.
pub struct RateLimiterGroup {
    inner: Arc<RateLimiterGroupInner>,
    driver: Option<ThreadDriver>,
}

struct ThreadDriver {
    _epoll_file: File,
    kill_evt: EventFd,
    epoll_thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
enum EpollDispatch {
    Kill = 1,
    Unblocked = 2,
    Unknown,
}

impl From<u64> for EpollDispatch {
    fn from(v: u64) -> Self {
        use EpollDispatch::*;
        match v {
            1 => Kill,
            2 => Unblocked,
            _ => Unknown,
        }
    }
}

impl RateLimiterGroup {
    /// Create a new RateLimiterGroup.
    pub fn new(
        id: &str,
        bytes_total_capacity: u64,
        bytes_one_time_burst: u64,
        bytes_complete_refill_time_ms: u64,
        ops_total_capacity: u64,
        ops_one_time_burst: u64,
        ops_complete_refill_time_ms: u64,
    ) -> result::Result<Self, Error> {
        let rate_limiter = RateLimiter::new(
            bytes_total_capacity,
            bytes_one_time_burst,
            bytes_complete_refill_time_ms,
            ops_total_capacity,
            ops_one_time_burst,
            ops_complete_refill_time_ms,
        )
        .map_err(Error::RateLimiter)?;

        Ok(Self {
            inner: Arc::new(RateLimiterGroupInner {
                id: id.to_string(),
                rate_limiter,
                handles: Mutex::new(Vec::new()),
            }),
            driver: None,
        })
    }

    /// Observe the limiter shared by the attached consumers.
    pub fn state(&self) -> RateLimiterState {
        self.inner.rate_limiter.managed_state()
    }

    /// Change the shared bandwidth policy and wake consumers only on real change.
    pub fn update_bandwidth(&self, target: Option<BucketConfig>) -> result::Result<bool, Error> {
        let changed = self
            .inner
            .rate_limiter
            .update_bandwidth(target)
            .map_err(Error::RateLimiter)?;
        if changed {
            self.inner.notify()?;
        }
        Ok(changed)
    }

    /// Whether an existing device queue, rather than a group thread, owns the timer.
    pub fn is_externally_driven(&self) -> bool {
        self.driver.is_none()
    }

    /// Timer watched by queue zero for an externally driven group.
    pub fn timer_fd(&self) -> RawFd {
        self.inner.rate_limiter.as_raw_fd()
    }

    /// Service the same timer and broadcast the resulting readiness to every queue.
    pub fn process_timer(&self) -> result::Result<(), Error> {
        self.inner.process_timer()
    }

    /// Create a new RateLimiterGroupHandle.
    pub fn new_handle(&self) -> result::Result<RateLimiterGroupHandle, Error> {
        RateLimiterGroupHandle::new(self.inner.clone())
    }

    /// Start a worker thread to broadcast an event to each RateLimiterGroupHandle
    /// when the RateLimiter becomes unblocked.
    pub fn start_thread(&mut self, exit_evt: EventFd) -> result::Result<(), Error> {
        if self.driver.is_some() {
            return Ok(());
        }
        let epoll_fd = epoll::create(true).map_err(Error::Epoll)?;
        // SAFETY: epoll_fd is a newly created valid descriptor, owned only here.
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };
        let kill_evt =
            EventFd::new(libc::EFD_NONBLOCK | libc::EFD_CLOEXEC).map_err(Error::EventFd)?;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, EpollDispatch::Kill as u64),
        )
        .map_err(Error::Epoll)?;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.timer_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, EpollDispatch::Unblocked as u64),
        )
        .map_err(Error::Epoll)?;
        let inner = self.inner.clone();
        let thread = thread::Builder::new()
            .name(format!("rate-limit-group-{}", inner.id))
            .spawn(move || {
                let res = std::panic::catch_unwind(AssertUnwindSafe(move || {
                    const EPOLL_EVENTS_LEN: usize = 2;

                    let mut events =
                        [epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

                    loop {
                        let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                            Ok(res) => res,
                            Err(e) => {
                                if e.kind() == io::ErrorKind::Interrupted {
                                    continue;
                                }
                                return Err(Error::Epoll(e));
                            }
                        };

                        for event in events.iter().take(num_events) {
                            let dispatch_event: EpollDispatch = event.data.into();
                            match dispatch_event {
                                EpollDispatch::Unknown => {
                                    let event = event.data;
                                    warn!("Unknown rate-limiter loop event: {event}");
                                }
                                EpollDispatch::Unblocked => {
                                    inner.process_timer()?;
                                }
                                EpollDispatch::Kill => {
                                    info!(
                                        "KILL_EVENT received, stopping rate-limit-group epoll loop"
                                    );
                                    return Ok(());
                                }
                            }
                        }
                    }
                }));

                match res {
                    Ok(res) => {
                        if let Err(e) = res {
                            error!("Error running rate-limit-group worker: {e:?}");
                            exit_evt.write(1).unwrap();
                        }
                    }
                    Err(_) => {
                        error!("rate-limit-group worker panicked");
                        exit_evt.write(1).unwrap();
                    }
                }
            })
            .map_err(Error::ThreadSpawn)?;
        self.driver = Some(ThreadDriver {
            _epoll_file: epoll_file,
            kill_evt,
            epoll_thread: Some(thread),
        });
        Ok(())
    }
}

impl Drop for RateLimiterGroup {
    fn drop(&mut self) {
        let Some(driver) = self.driver.as_mut() else {
            return;
        };
        driver.kill_evt.write(1).unwrap();

        if let Some(t) = driver.epoll_thread.take()
            && let Err(e) = t.join()
        {
            error!("Error joining thread: {e:?}");
        }
    }
}

#[cfg(test)]
pub(crate) mod unit_tests {
    use std::os::fd::AsRawFd;
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::eventfd::EventFd;

    use super::RateLimiterGroupHandle;
    use crate::group::RateLimiterGroup;
    use crate::{REFILL_TIMER_INTERVAL_MS, TokenBucket, TokenType};

    impl RateLimiterGroupHandle {
        fn bandwidth(&self) -> Option<TokenBucket> {
            let guard = self.inner.rate_limiter.inner.lock().unwrap();
            guard.bandwidth.clone()
        }

        fn ops(&self) -> Option<TokenBucket> {
            let guard = self.inner.rate_limiter.inner.lock().unwrap();
            guard.ops.clone()
        }
    }

    #[test]
    fn live_external_consumers_share_debt_and_changed_policy_wakes_all() {
        let group = RateLimiterGroup::new("disk-a", 100, 0, 1_000_000, 0, 0, 0).unwrap();
        let first = group.new_handle().unwrap();
        let second = group.new_handle().unwrap();
        assert!(first.consume(60, TokenType::Bytes));
        assert!(!second.consume(60, TokenType::Bytes));
        first.account_transferred(100, 0).unwrap();
        assert_eq!(group.state().bandwidth.debt, 60);
        assert!(group.is_externally_driven());
        assert!(group.update_bandwidth(None).unwrap());
        assert!(!first.is_blocked());
        assert_eq!(first.eventfd.read().unwrap(), 1);
        assert_eq!(second.eventfd.read().unwrap(), 1);
        assert!(
            group
                .update_bandwidth(Some(crate::BucketConfig {
                    size: 200,
                    one_time_burst: 2000,
                    refill_time: 1_000_000,
                }))
                .unwrap()
        );
        assert_eq!(group.state().bandwidth.debt, 60);
        assert_eq!(group.state().bandwidth.burst, 0);
        assert!(second.is_blocked());
    }

    #[test]
    fn live_unchanged_group_never_notifies_or_renews_credit() {
        let group = RateLimiterGroup::new("net-rx", 100, 1000, 1_000_000, 0, 0, 0).unwrap();
        let handle = group.new_handle().unwrap();
        handle.account_transferred(1200, 1).unwrap();
        let before = group.state();
        assert!(
            !group
                .update_bandwidth(Some(crate::BucketConfig {
                    size: 100,
                    one_time_burst: 1000,
                    refill_time: 1_000_000,
                }))
                .unwrap()
        );
        assert_eq!(group.state(), before);
        assert_eq!(
            handle.eventfd.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        handle.event_handler().unwrap();
        group.process_timer().unwrap();
        assert_eq!(group.state(), before);
    }

    #[test]
    fn live_notification_saturation_is_already_pending() {
        let group = RateLimiterGroup::new("net-tx", 100, 0, 1_000_000, 0, 0, 0).unwrap();
        let handle = group.new_handle().unwrap();
        handle.eventfd.write(u64::MAX - 1).unwrap();
        assert!(group.update_bandwidth(None).unwrap());
        assert_eq!(handle.eventfd.read().unwrap(), u64::MAX - 1);
    }

    #[test]
    fn live_external_timer_broadcasts_to_every_queue() {
        let group = RateLimiterGroup::new("net-rx", 100, 0, 10, 0, 0, 0).unwrap();
        let first = group.new_handle().unwrap();
        let second = group.new_handle().unwrap();
        first.account_transferred(200, 0).unwrap();
        let mut poll = libc::pollfd {
            fd: group.timer_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized pollfd for a live timer.
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 1000) }, 1);
        group.process_timer().unwrap();
        assert!(!second.is_blocked());
        assert_eq!(first.eventfd.read().unwrap(), 1);
        assert_eq!(second.eventfd.read().unwrap(), 1);
    }

    #[test]
    fn live_late_completed_packet_cannot_cancel_sleeping_peers_wake() {
        let group = RateLimiterGroup::new("net-rx", 100, 0, 1000, 0, 0, 0).unwrap();
        let first = group.new_handle().unwrap();
        let peer = group.new_handle().unwrap();
        first.account_transferred(200, 0).unwrap();
        {
            let mut inner = group.inner.rate_limiter.inner.lock().unwrap();
            inner.bandwidth.as_mut().unwrap().last_update =
                std::time::Instant::now() - Duration::from_secs(2);
        }
        first.account_transferred(1, 0).unwrap();
        assert_eq!(group.state().bandwidth.debt, 0);
        assert!(peer.is_blocked());
        wait_for_external_timer(&group);
        assert!(!peer.is_blocked());
        assert_eq!(peer.eventfd.read().unwrap(), 1);
    }

    #[test]
    fn live_rollback_cannot_cancel_sleeping_peers_wake() {
        let group = RateLimiterGroup::new("disk-a", 100, 0, 1_000_000, 0, 0, 0).unwrap();
        let first = group.new_handle().unwrap();
        let peer = group.new_handle().unwrap();
        assert!(first.consume(101, TokenType::Bytes));
        first.manual_replenish(101, TokenType::Bytes);
        assert_eq!(group.state().bandwidth.debt, 0);
        wait_for_external_timer(&group);
        assert!(!peer.is_blocked());
        assert_eq!(peer.eventfd.read().unwrap(), 1);
    }

    fn wait_for_handle_event(handle: &RateLimiterGroupHandle) {
        let mut poll = libc::pollfd {
            fd: handle.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized pollfd for a subscribed handle.
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 1000) }, 1);
        handle.event_handler().unwrap();
    }

    fn wait_for_external_timer(group: &RateLimiterGroup) {
        let mut poll = libc::pollfd {
            fd: group.timer_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized pollfd for a live timer.
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 1000) }, 1);
        group.process_timer().unwrap();
    }

    #[test]
    fn test_rate_limiter_group_new() {
        let l = RateLimiterGroup::new("test", 1000, 1001, 1002, 1003, 1004, 1005).unwrap();
        let h = l.new_handle().unwrap();
        let bw = h.bandwidth().unwrap();
        assert_eq!(bw.capacity(), 1000);
        assert_eq!(bw.one_time_burst(), 1001);
        assert_eq!(bw.refill_time_ms(), 1002);
        assert_eq!(bw.budget(), 1000);

        let ops = h.ops().unwrap();
        assert_eq!(ops.capacity(), 1003);
        assert_eq!(ops.one_time_burst(), 1004);
        assert_eq!(ops.refill_time_ms(), 1005);
        assert_eq!(ops.budget(), 1003);
    }

    #[test]
    fn test_rate_limiter_group_manual_replenish() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let l = RateLimiterGroup::new("test", 1000, 0, 1000, 1000, 0, 1000).unwrap();
        let h = l.new_handle().unwrap();

        // consume 123 bytes
        assert!(h.consume(123, TokenType::Bytes));
        h.inner
            .rate_limiter
            .inner
            .lock()
            .unwrap()
            .bandwidth
            .as_mut()
            .unwrap()
            .last_update = std::time::Instant::now() + Duration::from_secs(60);
        h.manual_replenish(23, TokenType::Bytes);
        {
            let bytes_tb = h.bandwidth().unwrap();
            assert_eq!(bytes_tb.budget(), 900);
        }
        // consume 123 ops
        assert!(h.consume(123, TokenType::Ops));
        h.inner
            .rate_limiter
            .inner
            .lock()
            .unwrap()
            .ops
            .as_mut()
            .unwrap()
            .last_update = std::time::Instant::now() + Duration::from_secs(60);
        h.manual_replenish(23, TokenType::Ops);
        {
            let bytes_tb = h.ops().unwrap();
            assert_eq!(bytes_tb.budget(), 900);
        }
    }

    #[test]
    fn test_rate_limiter_group_bandwidth() {
        // rate limiter with limit of 1000 bytes/s
        let mut l = RateLimiterGroup::new("test", 1000, 0, 1000, 0, 0, 0).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();

        // limiter should not be blocked
        assert!(!h.is_blocked());
        // raw FD for this disabled should be valid
        assert!(h.as_raw_fd() > 0);

        // ops/s limiter should be disabled so consume(whatever) should work
        assert!(h.consume(u64::MAX, TokenType::Ops));

        // do full 1000 bytes
        assert!(h.consume(1000, TokenType::Bytes));
        // try and fail on another 100
        assert!(!h.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(h.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(h.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        wait_for_handle_event(&h);
        // limiter should now be unblocked
        assert!(!h.is_blocked());
        // try and succeed on another 100 bytes this time
        assert!(h.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_group_ops() {
        // rate limiter with limit of 1000 ops/s
        let mut l = RateLimiterGroup::new("test", 0, 0, 0, 1000, 0, 1000).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();

        // limiter should not be blocked
        assert!(!h.is_blocked());
        // raw FD for this disabled should be valid
        assert!(h.as_raw_fd() > 0);

        // bytes/s limiter should be disabled so consume(whatever) should work
        assert!(h.consume(u64::MAX, TokenType::Bytes));

        // do full 1000 ops
        assert!(h.consume(1000, TokenType::Ops));
        // try and fail on another 100
        assert!(!h.consume(100, TokenType::Ops));
        // since consume failed, limiter should be blocked now
        assert!(h.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(h.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        wait_for_handle_event(&h);
        // limiter should now be unblocked
        assert!(!h.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(h.consume(100, TokenType::Ops));
    }

    #[test]
    fn test_rate_limiter_group_full() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let mut l = RateLimiterGroup::new("test", 1000, 0, 1000, 1000, 0, 1000).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();

        // limiter should not be blocked
        assert!(!h.is_blocked());
        // raw FD for this disabled should be valid
        assert!(h.as_raw_fd() > 0);

        // do full 1000 bytes
        assert!(h.consume(1000, TokenType::Ops));
        // do full 1000 bytes
        assert!(h.consume(1000, TokenType::Bytes));
        // try and fail on another 100 ops
        assert!(!h.consume(100, TokenType::Ops));
        // try and fail on another 100 bytes
        assert!(!h.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(h.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(h.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        wait_for_handle_event(&h);
        // limiter should now be unblocked
        assert!(!h.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(h.consume(100, TokenType::Ops));
        // try and succeed on another 100 bytes this time
        assert!(h.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_group_overconsumption() {
        // initialize the rate limiter
        let mut l = RateLimiterGroup::new("test", 1000, 0, 1000, 1000, 0, 1000).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();

        // try to consume 2.5x the bucket size
        // we are "borrowing" 1.5x the bucket size in tokens since
        // the bucket is full
        assert!(h.consume(2500, TokenType::Bytes));

        // check that even after a whole second passes, the rate limiter
        // is still blocked
        thread::sleep(Duration::from_millis(1000));
        assert!(h.is_blocked());

        // after 1.5x the replenish time has passed, the rate limiter
        // is available again
        thread::sleep(Duration::from_millis(500));
        wait_for_handle_event(&h);
        assert!(!h.is_blocked());

        // reset the rate limiter
        let mut l = RateLimiterGroup::new("test", 1000, 0, 1000, 1000, 0, 1000).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();
        // try to consume 1.5x the bucket size
        // we are "borrowing" 1.5x the bucket size in tokens since
        // the bucket is full, should arm the timer to 0.5x replenish
        // time, which is 500 ms
        assert!(h.consume(1500, TokenType::Bytes));

        // check that after more than the minimum refill time,
        // the rate limiter is still blocked
        thread::sleep(Duration::from_millis(200));
        assert!(h.is_blocked());

        // try to consume some tokens, which should fail as the timer
        // is still active
        assert!(!h.consume(100, TokenType::Bytes));
        assert!(h.is_blocked());

        // check that after the minimum refill time, the timer was not
        // overwritten and the rate limiter is still blocked from the
        // borrowing we performed earlier
        thread::sleep(Duration::from_millis(100));
        assert!(h.is_blocked());
        assert!(!h.consume(100, TokenType::Bytes));

        // after waiting out the full duration, rate limiter should be
        // available again
        thread::sleep(Duration::from_millis(200));
        wait_for_handle_event(&h);
        assert!(!h.is_blocked());
        assert_eq!(l.state().bandwidth.debt, 0);
        // Debt repayment does not also replenish ordinary credit.
        if !h.consume(100, TokenType::Bytes) {
            wait_for_handle_event(&h);
            assert!(h.consume(100, TokenType::Bytes));
        }
    }
}
