//! Hysteria2-style "brutal" congestion control, ported to quinn 0.11.
//!
//! Reference: hysteria `core/internal/congestion/brutal` (quic-go based).
//! The idea: the operator knows the link bandwidth, so the sender pins its
//! rate to that bandwidth instead of probing for it. The congestion window is
//! derived from the bandwidth-delay product and scaled by the measured ACK
//! rate (loss compensation), and loss never shrinks the window.
//!
//! Deviations from hysteria, forced by quinn's controller API
//! (`quinn_proto::congestion::Controller`):
//!
//! * **Window is one BDP, not two.** Hysteria sizes its window at
//!   `2 * bps * rtt / ackRate` and paces with a separate pacer at
//!   `bps / ackRate`; the 2x exists only to give that pacer headroom.
//!   quinn has no controller-owned pacer: its token-bucket pacer derives the
//!   send rate from the window itself (refill = 1.25 * window / rtt). A
//!   2x-BDP window would therefore make quinn send at ~2.5x the configured
//!   bandwidth. One BDP makes quinn pace at ~`bps / ackRate` (the 1.25x
//!   refill provides the burst headroom) while the window caps in-flight
//!   bytes at exactly `bps * rtt / ackRate`.
//! * **Losses are counted in bytes.** quinn reports lost *bytes* per
//!   congestion event; hysteria counts lost *packets*. Lost ack-eliciting
//!   packets are MTU-sized in practice, so the packet count is estimated as
//!   `lost_bytes / mtu` (rounded up).
//! * **RTT comes from quinn's `RttEstimator`.** Hysteria reads quic-go's
//!   `RTTStats.SmoothedRTT()`, an EWMA of send→ack samples *with the peer's
//!   ack delay discounted* (quic-go: `sample -= ackDelay`, clamped so the
//!   result never drops below min RTT). quinn's `RttEstimator::get()` is the
//!   same estimator with the same clamp, and it is handed to `on_ack`, so it
//!   is cached there and used for BDP sizing. Feeding the *raw* send→ack time
//!   instead would look more faithful but is not: the peer's delayed-ack
//!   timer (up to 25 ms) fires on a trickle of packets, and a raw-sample EWMA
//!   turns those rare spikes into a permanent window sawtooth, collapsing the
//!   window to its 2-MTU floor for ~98% of the time. quic-go discounts the
//!   ack delay for exactly this reason.
//! * **One bandwidth for both directions.** Hysteria negotiates
//!   `min(serverRx, clientTx)` in its auth response; quic-reality's
//!   authentication happens inside the QUIC Initial packet and has no
//!   post-handshake bandwidth exchange, so `quic.brutal_bandwidth` applies
//!   to both the client's and the server's sending side.

use quinn_proto::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Number of one-second sample slots kept (slot index = second % count).
const PKT_INFO_SLOT_COUNT: u64 = 5;
/// Minimum ack+loss samples in the window before the ACK rate leaves 1.0.
const MIN_SAMPLE_COUNT: u64 = 50;
/// ACK rate floor: the window is inflated by at most 1 / 0.8 for loss.
const MIN_ACK_RATE: f64 = 0.8;
/// Window used before the first RTT sample, as in hysteria (bytes).
const FALLBACK_WINDOW: u64 = 10240;
/// Seconds between debug prints of the ACK rate, as in hysteria.
const DEBUG_PRINT_INTERVAL: u64 = 2;

/// Builds a [`Brutal`] controller per connection.
///
/// `bps` is the target bandwidth in **bytes per second**.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    bps: u64,
    /// Pin the ACK rate at 1.0, i.e. never inflate the window for loss.
    disable_loss_compensation: bool,
}

impl BrutalConfig {
    pub fn new(bps: u64, disable_loss_compensation: bool) -> Self {
        Self {
            bps,
            disable_loss_compensation,
        }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self, current_mtu))
    }
}

/// One second of ACK/loss samples, as in hysteria's `pktInfo`.
#[derive(Debug, Clone, Copy, Default)]
struct PktInfo {
    /// Second-resolution timestamp; 0 means the slot was never written.
    timestamp: u64,
    ack_count: u64,
    loss_count: u64,
}

/// The brutal congestion controller.
#[derive(Debug)]
pub struct Brutal {
    config: Arc<BrutalConfig>,
    /// Target bandwidth in bytes per second.
    bps: u64,
    current_mtu: u64,
    /// Measured ACK rate in `[MIN_ACK_RATE, 1.0]`; scales window and pacing.
    ack_rate: f64,
    /// Latest `RttEstimator::get()` seen in `on_ack`; the quic-go
    /// `SmoothedRTT()` equivalent used for BDP sizing.
    rtt: Duration,
    /// Time of the first event; slot timestamps are seconds since it.
    epoch: Option<Instant>,
    slots: [PktInfo; PKT_INFO_SLOT_COUNT as usize],
    /// Last second at which the ACK rate was printed (debug only).
    last_debug_sec: u64,
}

impl Brutal {
    pub fn new(config: Arc<BrutalConfig>, current_mtu: u16) -> Self {
        Self {
            bps: config.bps,
            current_mtu: u64::from(current_mtu),
            config,
            ack_rate: 1.0,
            rtt: Duration::ZERO,
            epoch: None,
            slots: [PktInfo::default(); PKT_INFO_SLOT_COUNT as usize],
            last_debug_sec: 0,
        }
    }

    /// Seconds since the first event seen; sets the epoch on first use.
    fn secs(&mut self, now: Instant) -> u64 {
        match self.epoch {
            None => {
                self.epoch = Some(now);
                0
            }
            Some(epoch) => now.checked_duration_since(epoch).map_or(0, |d| d.as_secs()),
        }
    }

    /// Record one acked packet into the current second's slot.
    fn record_ack(&mut self, now: Instant) {
        let ts = self.secs(now);
        let slot = &mut self.slots[(ts % PKT_INFO_SLOT_COUNT) as usize];
        if slot.timestamp == ts {
            slot.ack_count += 1;
        } else {
            // Uninitialized slot or older than the slot window: start fresh.
            *slot = PktInfo {
                timestamp: ts,
                ack_count: 1,
                loss_count: 0,
            };
        }
        self.update_ack_rate(ts);
    }

    /// Record the losses of one congestion event into the current second's slot.
    fn record_loss(&mut self, now: Instant, lost_bytes: u64) {
        let ts = self.secs(now);
        // quinn reports lost bytes; hysteria counts lost packets. Lost
        // ack-eliciting packets are MTU-sized in practice, so divide by the
        // MTU (an ECN-only event carries 0 bytes and counts no loss).
        let lost = if lost_bytes == 0 {
            0
        } else {
            lost_bytes.div_ceil(self.current_mtu.max(1))
        };
        let slot = &mut self.slots[(ts % PKT_INFO_SLOT_COUNT) as usize];
        if slot.timestamp == ts {
            slot.loss_count += lost;
        } else {
            *slot = PktInfo {
                timestamp: ts,
                ack_count: 0,
                loss_count: lost,
            };
        }
        self.update_ack_rate(ts);
    }

    /// Recompute the ACK rate over the last `PKT_INFO_SLOT_COUNT` seconds.
    fn update_ack_rate(&mut self, now_sec: u64) {
        if self.config.disable_loss_compensation {
            self.ack_rate = 1.0;
            return;
        }
        let min_timestamp = now_sec.saturating_sub(PKT_INFO_SLOT_COUNT);
        let (mut ack_count, mut loss_count) = (0u64, 0u64);
        for info in &self.slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }
        if ack_count + loss_count < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            return;
        }
        let rate = ack_count as f64 / (ack_count + loss_count) as f64;
        self.ack_rate = rate.max(MIN_ACK_RATE);
        if now_sec.saturating_sub(self.last_debug_sec) >= DEBUG_PRINT_INTERVAL {
            self.last_debug_sec = now_sec;
            debug!(
                ack_rate = format!("{:.2}", self.ack_rate),
                total = ack_count + loss_count,
                ack = ack_count,
                loss = loss_count,
                rtt_ms = format!("{:.0}", self.rtt.as_secs_f64() * 1000.0),
                cwnd = self.window(),
                mtu = self.current_mtu,
                "brutal: ACK rate updated"
            );
        }
    }
}

impl Controller for Brutal {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, _last_packet_number: u64) {
        // quinn's own pacer (driven by window()) handles send pacing;
        // hysteria's per-packet pacer hook has no counterpart here.
    }

    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // quinn's RttEstimator subtracts the peer's ack delay (clamped at
        // min RTT), which is exactly what quic-go's RTTStats.SmoothedRTT()
        // hands hysteria's brutal — cache it for BDP sizing.
        self.rtt = rtt.get();
        self.record_ack(now);
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        // Hysteria recomputes the ACK rate once per congestion-event batch
        // (OnCongestionEventEx). quinn splits that batch into per-packet
        // on_ack calls plus this marker, and record_ack already recomputes.
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // Hysteria ignores everything but the acked/lost packet counts; the
        // same holds here. Loss never shrinks the window, it only lowers the
        // ACK rate (which inflates the window to push through the loss).
        self.record_loss(now, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = u64::from(new_mtu);
    }

    fn window(&self) -> u64 {
        let rtt = self.rtt;
        if rtt.is_zero() {
            return self.initial_window();
        }
        let bdp = self.bps as f64 * rtt.as_secs_f64() / self.ack_rate;
        // Never block the path entirely: quinn's other controllers floor
        // their window at 2 MTU, and the pacer asserts a non-zero window.
        (bdp as u64).max(2 * self.current_mtu)
    }

    fn metrics(&self) -> ControllerMetrics {
        // ControllerMetrics is #[non_exhaustive]: build via Default and
        // assign the public fields.
        let mut m = ControllerMetrics::default();
        m.congestion_window = self.window();
        m.ssthresh = None;
        // Target pacing rate in bits per second (what qlog expects).
        m.pacing_rate = Some((self.bps as f64 * 8.0 / self.ack_rate) as u64);
        m
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Brutal {
            config: Arc::clone(&self.config),
            bps: self.bps,
            current_mtu: self.current_mtu,
            ack_rate: self.ack_rate,
            rtt: self.rtt,
            epoch: self.epoch,
            slots: self.slots,
            last_debug_sec: self.last_debug_sec,
        })
    }

    fn initial_window(&self) -> u64 {
        FALLBACK_WINDOW.max(2 * self.current_mtu)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brutal(bps: u64, disable_loss_compensation: bool) -> Brutal {
        Brutal::new(
            Arc::new(BrutalConfig::new(bps, disable_loss_compensation)),
            1200,
        )
    }

    /// Drive one second of samples through the controller and return the
    /// resulting ACK rate, mirroring hysteria's `feedAckRate` test helper.
    fn feed_ack_rate(
        disable_loss_compensation: bool,
        ack_count: u64,
        loss_count: u64,
    ) -> f64 {
        let mut b = brutal(1_000_000, disable_loss_compensation);
        let now = Instant::now();
        for _ in 0..ack_count {
            b.record_ack(now);
        }
        b.record_loss(now, loss_count * 1200);
        b.ack_rate
    }

    #[test]
    fn ack_rate_matches_hysteria_table() {
        // Same table as hysteria's brutal_test.go.
        let cases = [
            (100, 0, 1.0),   // no loss
            (80, 20, 0.8),   // 20% loss
            (50, 50, 0.8),   // clamped up to the floor
            (10, 5, 1.0),    // below minSampleCount, stays 1
        ];
        for (ack, loss, want) in cases {
            assert_eq!(feed_ack_rate(false, ack, loss), want, "ack={ack} loss={loss}");
            // Compensation disabled: pinned at 1 regardless of loss.
            assert_eq!(feed_ack_rate(true, ack, loss), 1.0, "ack={ack} loss={loss}");
        }
    }

    #[test]
    fn window_is_one_bdp() {
        // 8 Mbps = 1,000,000 bytes/s; 50 ms RTT -> 50,000 bytes in flight.
        let mut b = brutal(8_000_000 / 8, false);
        assert_eq!(b.window(), FALLBACK_WINDOW, "no RTT sample yet");
        b.rtt = Duration::from_millis(50);
        assert_eq!(b.window(), 50_000);
    }

    #[test]
    fn window_scales_with_ack_rate_and_mtu() {
        let mut b = brutal(8_000_000 / 8, false);
        b.rtt = Duration::from_millis(50);
        assert_eq!(b.window(), 50_000);
        b.ack_rate = MIN_ACK_RATE;
        assert_eq!(b.window(), 62_500, "loss compensation inflates the window");
        // Tiny BDP still gets 2 MTU so the path is never blocked.
        let mut b = brutal(8_000_000 / 8, false);
        b.rtt = Duration::from_micros(100);
        assert_eq!(b.window(), 2 * 1200);
    }

    #[test]
    fn samples_older_than_five_seconds_drop_out() {
        let mut b = brutal(1_000_000, false);
        let t0 = Instant::now();
        for _ in 0..60 {
            b.record_ack(t0);
        }
        assert_eq!(b.ack_rate, 1.0);
        // Six seconds later only the new samples count: 40 ack + 10 loss
        // is exactly minSampleCount, rate 0.8. If the old 60 acks were
        // still counted the rate would be 100/110.
        let t1 = t0 + Duration::from_secs(6);
        for _ in 0..40 {
            b.record_ack(t1);
        }
        b.record_loss(t1, 10 * 1200);
        assert_eq!(b.ack_rate, 0.8);
    }

    #[test]
    fn metrics_report_pacing_rate_in_bits() {
        let b = brutal(8_000_000 / 8, false);
        let m = b.metrics();
        assert_eq!(m.pacing_rate, Some(8_000_000), "bits per second");
        assert_eq!(m.congestion_window, b.window());
        assert_eq!(m.ssthresh, None);
    }

    #[test]
    fn clone_box_preserves_state() {
        let mut b = brutal(8_000_000 / 8, false);
        b.rtt = Duration::from_millis(50);
        let now = Instant::now();
        for _ in 0..60 {
            b.record_ack(now);
        }
        b.record_loss(now, 20 * 1200);
        let cloned = b.clone_box();
        let cloned = cloned.into_any().downcast::<Brutal>().unwrap();
        assert_eq!(cloned.ack_rate, 0.8);
        assert_eq!(cloned.window(), b.window());
        assert_eq!(cloned.rtt, b.rtt);
    }

    #[test]
    fn mtu_update_feeds_loss_counting_and_window_floor() {
        let mut b = brutal(8_000_000 / 8, false);
        b.on_mtu_update(9000);
        b.rtt = Duration::from_micros(10);
        assert_eq!(b.window(), 2 * 9000);
        // A 9000-byte loss is one packet at the new MTU, not seven.
        let now = Instant::now();
        b.record_loss(now, 9000);
        assert_eq!(b.slots.iter().map(|s| s.loss_count).sum::<u64>(), 1);
    }
}
