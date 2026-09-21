//! Bounded FIFO publication admission shared by capture and maintenance.

use std::{
    collections::VecDeque,
    marker::PhantomData,
    rc::Rc,
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};

use contextdb_service::{ErrorCode, ServiceError, ServiceResult};

use super::integrity;

const CAPACITY: usize = 64;
const MAX_WAIT: Duration = Duration::from_secs(30);
const CANCEL_POLL: Duration = Duration::from_millis(2);

#[derive(Debug, Default)]
struct State {
    next: u64,
    waiting: VecDeque<u64>,
    active: Option<u64>,
    poisoned: bool,
}

#[derive(Debug, Default)]
pub(super) struct PublicationQueue {
    state: Mutex<State>,
    changed: Condvar,
}

pub(super) struct PublicationGuard<'a> {
    queue: &'a PublicationQueue,
    ticket: u64,
    // Preserve the old native mutex guard's thread affinity.
    _thread: PhantomData<Rc<()>>,
}

impl PublicationQueue {
    /// Opportunistic recovery must not wait behind or overtake a publisher.
    pub(super) fn try_enter(&self) -> ServiceResult<Option<PublicationGuard<'_>>> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(poisoned()),
        };
        if state.poisoned {
            return Err(poisoned());
        }
        if state.active.is_some() || !state.waiting.is_empty() {
            return Ok(None);
        }
        let ticket = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| pressure("publication ticket exhausted"))?;
        state.active = Some(ticket);
        Ok(Some(PublicationGuard {
            queue: self,
            ticket,
            _thread: PhantomData,
        }))
    }

    /// Capacity includes the active publisher. A rejected/cancelled waiter owns
    /// no publication slot and has performed no native transaction.
    pub(super) fn enter(
        &self,
        check: impl Fn() -> ServiceResult<()>,
    ) -> ServiceResult<PublicationGuard<'_>> {
        let started = Instant::now();
        check()?;
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        if state.poisoned {
            return Err(poisoned());
        }
        if state.waiting.len() + usize::from(state.active.is_some()) >= CAPACITY {
            return Err(pressure(
                "native publication queue is full; retry the same identity",
            ));
        }
        let ticket = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| pressure("publication ticket exhausted"))?;
        state.waiting.push_back(ticket);
        self.changed.notify_all();
        loop {
            let valid = if state.poisoned {
                Err(poisoned())
            } else {
                check().and_then(|()| {
                    if started.elapsed() >= MAX_WAIT {
                        Err(pressure("native publication wait exceeded 30 seconds"))
                    } else {
                        Ok(())
                    }
                })
            };
            if let Err(error) = valid {
                state.waiting.retain(|candidate| *candidate != ticket);
                self.changed.notify_all();
                return Err(error);
            }
            if state.active.is_none() && state.waiting.front() == Some(&ticket) {
                state.waiting.pop_front();
                state.active = Some(ticket);
                return Ok(PublicationGuard {
                    queue: self,
                    ticket,
                    _thread: PhantomData,
                });
            }
            state = self
                .changed
                .wait_timeout(state, CANCEL_POLL)
                .map_err(|_| poisoned())?
                .0;
        }
    }
}

impl Drop for PublicationGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.queue.state.lock() {
            state.poisoned |= std::thread::panicking() || state.active != Some(self.ticket);
            state.active = None;
        }
        self.queue.changed.notify_all();
    }
}

fn poisoned() -> ServiceError {
    integrity("native publication queue is poisoned")
}

fn pressure(message: &str) -> ServiceError {
    ServiceError::new(ErrorCode::ResourceExhausted, message, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };

    fn wait_count(queue: &PublicationQueue, count: usize) {
        let state = queue.state.lock().expect("queue");
        let (state, _) = queue
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| {
                state.waiting.len() != count
            })
            .expect("wait for enqueue");
        assert_eq!(state.waiting.len(), count);
    }

    #[test]
    fn publishers_run_fifo_and_capacity_rejection_never_overtakes_them() {
        let queue = Arc::new(PublicationQueue::default());
        let active = queue.enter(|| Ok(())).expect("hold publisher");
        let (send, receive) = mpsc::channel();
        std::thread::scope(|threads| {
            for index in 0..CAPACITY - 1 {
                let worker_queue = Arc::clone(&queue);
                let send = send.clone();
                threads.spawn(move || {
                    let _guard = worker_queue.enter(|| Ok(())).expect("queued publisher");
                    send.send(index).expect("order");
                });
                wait_count(&queue, index + 1);
            }
            assert!(
                matches!(queue.enter(|| Ok(())), Err(error) if error.code == ErrorCode::ResourceExhausted)
            );
            drop(active);
            for index in 0..CAPACITY - 1 {
                assert_eq!(
                    receive
                        .recv_timeout(Duration::from_secs(5))
                        .expect("publication"),
                    index
                );
            }
        });
        assert!(queue.enter(|| Ok(())).is_ok(), "capacity is released");
    }

    #[test]
    fn cancelled_waiter_releases_its_place_before_the_next_publication() {
        let queue = Arc::new(PublicationQueue::default());
        let active = queue.enter(|| Ok(())).expect("hold publisher");
        let cancel = AtomicBool::new(false);
        std::thread::scope(|threads| {
            let cancelled = threads.spawn(|| {
                queue
                    .enter(|| {
                        if cancel.load(Ordering::Acquire) {
                            Err(ServiceError::new(
                                ErrorCode::BudgetExhausted,
                                "cancelled",
                                false,
                            ))
                        } else {
                            Ok(())
                        }
                    })
                    .is_err()
            });
            wait_count(&queue, 1);
            let next = threads.spawn(|| {
                let _guard = queue.enter(|| Ok(())).expect("next publisher");
            });
            wait_count(&queue, 2);
            cancel.store(true, Ordering::Release);
            assert!(cancelled.join().expect("cancelled waiter"));
            wait_count(&queue, 1);
            drop(active);
            next.join().expect("unblocked publisher");
        });
    }

    #[test]
    fn panicking_publisher_poisoning_survives_guard_drop() {
        let queue = Arc::new(PublicationQueue::default());
        let worker_queue = Arc::clone(&queue);
        assert!(
            std::thread::spawn(move || {
                let _guard = worker_queue.enter(|| Ok(())).expect("publisher");
                panic!("publication interrupted");
            })
            .join()
            .is_err()
        );
        assert!(
            matches!(queue.enter(|| Ok(())), Err(error) if error.code == ErrorCode::IntegrityFailure)
        );
    }
}
