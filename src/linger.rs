//! Deferred drops: keep a value alive for a while, then let it go.
//!
//! The registry lingers an encoder after its last listener leaves, and an
//! engine pull after its last encoder stops, by parking an `Arc` here (see
//! `registry`). One thread serves every linger, rather than one sleeping
//! thread per departure — a client that flaps would otherwise leave a trail of
//! them.

use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

type Held = (Instant, Box<dyn Send>);

/// Keep `value` alive for `period`, then drop it on the linger thread. A zero
/// period drops it now, as does a linger thread that could not be started.
pub fn hold<T: Send + 'static>(value: T, period: Duration) {
    if period.is_zero() {
        return;
    }
    if let Some(tx) = reaper() {
        // A send can only fail if the thread has died, and then the value
        // comes back in the error and drops here: an un-lingered teardown.
        let _ = tx.send((Instant::now() + period, Box::new(value)));
    }
}

fn reaper() -> Option<&'static Sender<Held>> {
    static TX: OnceLock<Option<Sender<Held>>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = channel();
        thread::Builder::new()
            .name("linger".into())
            .spawn(move || run(rx))
            .ok()
            .map(|_| tx)
    })
    .as_ref()
}

fn run(rx: Receiver<Held>) {
    // A handful of entries at most, so a scan beats a heap for simplicity.
    let mut held: Vec<Held> = Vec::new();
    loop {
        let next = held.iter().map(|(until, _)| *until).min();
        let got = match next {
            Some(until) => rx.recv_timeout(until.saturating_duration_since(Instant::now())),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match got {
            Ok(entry) => held.push(entry),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        // Expired values drop here, on this thread. A drop may call `hold`
        // again (an encoder's last drop lingers its engine pull), which only
        // sends on the channel and so cannot deadlock against this loop.
        let now = Instant::now();
        held.retain(|(until, _)| *until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn eventually(cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    #[test]
    fn holds_a_value_for_the_period_then_drops_it() {
        let v = Arc::new(());
        hold(v.clone(), Duration::from_millis(100));
        assert_eq!(Arc::strong_count(&v), 2, "held");
        assert!(eventually(|| Arc::strong_count(&v) == 1), "released");
    }

    #[test]
    fn a_zero_period_drops_at_once() {
        let v = Arc::new(());
        hold(v.clone(), Duration::ZERO);
        assert_eq!(Arc::strong_count(&v), 1);
    }

    #[test]
    fn a_short_linger_is_not_held_up_behind_a_long_one() {
        let long = Arc::new(());
        let short = Arc::new(());
        hold(long.clone(), Duration::from_secs(3600));
        hold(short.clone(), Duration::from_millis(50));
        assert!(eventually(|| Arc::strong_count(&short) == 1));
        assert_eq!(Arc::strong_count(&long), 2);
    }
}
