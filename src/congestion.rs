//! Congestion control: BBR, Cubic, and a port of Hysteria2's Brutal controller.
//!
//! Brutal abandons loss-based backoff and instead paces to an explicit
//! bandwidth target, scaling the congestion window to the bandwidth-delay
//! product. That is what makes "hy2 speed" work on clean links; on lossy links
//! plain BBR is the safer default, hence the configurable switch.

use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn_proto::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

const SAMPLE_SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE_NUMERATOR: u64 = 4;
const MIN_ACK_RATE_DENOMINATOR: u64 = 5;
const CONGESTION_WINDOW_MULTIPLIER: u128 = 2;
const INITIAL_WINDOW: u64 = 10_240;

/// Which controller a connection uses.
#[derive(Debug, Clone)]
pub enum CongestionKind {
    /// quinn's stock BBR.
    Bbr,
    /// Stock Cubic.
    Cubic,
    /// Brutal with an explicit bandwidth target in bytes/second.
    Brutal(u64),
}

impl Default for CongestionKind {
    fn default() -> Self {
        Self::Bbr
    }
}

/// Builds controllers for new connections.
#[derive(Debug)]
pub struct CongestionConfig {
    kind: CongestionKind,
}

impl CongestionConfig {
    pub fn new(kind: CongestionKind) -> Self {
        Self { kind }
    }
}

impl ControllerFactory for CongestionConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let fallback: Box<dyn Controller> = match self.kind {
            CongestionKind::Bbr => Arc::new(BbrConfig::default()).build(now, current_mtu),
            CongestionKind::Cubic => {
                Arc::new(quinn_proto::congestion::CubicConfig::default()).build(now, current_mtu)
            }
            CongestionKind::Brutal(_) => Arc::new(BbrConfig::default()).build(now, current_mtu),
        };
        Box::new(AdaptiveCongestion {
            brutal: Brutal::new(
                Arc::new(BrutalControl {
                    enabled: AtomicBool::new(matches!(self.kind, CongestionKind::Brutal(_))),
                    bandwidth: AtomicU64::new(match self.kind {
                        CongestionKind::Brutal(bps) => bps,
                        _ => 0,
                    }),
                    mtu: AtomicU64::new(current_mtu as u64),
                }),
                now,
                current_mtu,
            ),
            fallback,
        })
    }
}

/// Shared Brutal parameters; can be reconfigured per connection.
struct BrutalControl {
    enabled: AtomicBool,
    /// Bytes per second.
    bandwidth: AtomicU64,
    mtu: AtomicU64,
}

impl std::fmt::Debug for BrutalControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrutalControl")
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .field("bandwidth", &self.bandwidth.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Brutal when enabled, otherwise the configured fallback (BBR/Cubic).
struct AdaptiveCongestion {
    brutal: Brutal,
    fallback: Box<dyn Controller>,
}

impl std::fmt::Debug for AdaptiveCongestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdaptiveCongestion")
            .field("brutal", &self.brutal)
            .finish_non_exhaustive()
    }
}

impl Controller for AdaptiveCongestion {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        if self.brutal.enabled() {
            self.brutal.on_sent(now, bytes, last_packet_number);
        } else {
            self.fallback.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if self.brutal.enabled() {
            self.brutal.on_ack(now, sent, bytes, app_limited, rtt);
        } else {
            self.fallback.on_ack(now, sent, bytes, app_limited, rtt);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if self.brutal.enabled() {
            self.brutal
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        } else {
            self.fallback
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if self.brutal.enabled() {
            self.brutal
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        } else {
            self.fallback
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.brutal.on_mtu_update(new_mtu);
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        if self.brutal.enabled() {
            self.brutal.window()
        } else {
            self.fallback.window()
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        if self.brutal.enabled() {
            self.brutal.metrics()
        } else {
            self.fallback.metrics()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(AdaptiveCongestion {
            brutal: self.brutal.clone(),
            fallback: self.fallback.clone_box(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.fallback.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PacketInfo {
    timestamp: Option<u64>,
    ack_count: u64,
    loss_count: u64,
}

/// Hysteria2's Brutal controller (ported from hysteria-rust).
#[derive(Debug, Clone)]
struct Brutal {
    control: Arc<BrutalControl>,
    origin: Instant,
    smoothed_rtt: Duration,
    slots: [PacketInfo; SAMPLE_SLOT_COUNT],
    ack_rate_numerator: u64,
    ack_rate_denominator: u64,
}

impl Brutal {
    fn new(control: Arc<BrutalControl>, origin: Instant, current_mtu: u16) -> Self {
        // Keep the MTU fresh if the factory already learned a better one.
        if control.mtu.load(Ordering::Relaxed) < u64::from(current_mtu) {
            control.mtu.store(u64::from(current_mtu), Ordering::Relaxed);
        }
        Self {
            control,
            origin,
            smoothed_rtt: Duration::ZERO,
            slots: [PacketInfo::default(); SAMPLE_SLOT_COUNT],
            ack_rate_numerator: 1,
            ack_rate_denominator: 1,
        }
    }

    fn enabled(&self) -> bool {
        self.control.enabled.load(Ordering::Acquire)
    }

    fn record(&mut self, now: Instant, acknowledgements: u64, losses: u64) {
        let timestamp = now.saturating_duration_since(self.origin).as_secs();
        let slot = usize::try_from(timestamp % SAMPLE_SLOT_COUNT as u64)
            .expect("slot index always fits usize");
        let info = &mut self.slots[slot];
        if info.timestamp == Some(timestamp) {
            info.ack_count = info.ack_count.saturating_add(acknowledgements);
            info.loss_count = info.loss_count.saturating_add(losses);
        } else {
            *info = PacketInfo {
                timestamp: Some(timestamp),
                ack_count: acknowledgements,
                loss_count: losses,
            };
        }
        self.update_ack_rate(timestamp);
    }

    fn update_ack_rate(&mut self, timestamp: u64) {
        let minimum_timestamp = timestamp.saturating_sub(SAMPLE_SLOT_COUNT as u64);
        let (acknowledgements, losses) = self
            .slots
            .iter()
            .filter(|slot| slot.timestamp.is_some_and(|value| value >= minimum_timestamp))
            .fold((0_u64, 0_u64), |(ack, loss), slot| {
                (
                    ack.saturating_add(slot.ack_count),
                    loss.saturating_add(slot.loss_count),
                )
            });
        let samples = acknowledgements.saturating_add(losses);
        if samples < MIN_SAMPLE_COUNT {
            self.ack_rate_numerator = 1;
            self.ack_rate_denominator = 1;
            return;
        }
        if acknowledgements.saturating_mul(MIN_ACK_RATE_DENOMINATOR)
            < samples.saturating_mul(MIN_ACK_RATE_NUMERATOR)
        {
            self.ack_rate_numerator = MIN_ACK_RATE_NUMERATOR;
            self.ack_rate_denominator = MIN_ACK_RATE_DENOMINATOR;
        } else {
            self.ack_rate_numerator = acknowledgements;
            self.ack_rate_denominator = samples;
        }
    }

    fn target_window(&self) -> u64 {
        if self.smoothed_rtt.is_zero() {
            return INITIAL_WINDOW;
        }
        let numerator = u128::from(self.control.bandwidth.load(Ordering::Acquire))
            .saturating_mul(self.smoothed_rtt.as_nanos())
            .saturating_mul(CONGESTION_WINDOW_MULTIPLIER)
            .saturating_mul(u128::from(self.ack_rate_denominator));
        let denominator =
            1_000_000_000_u128.saturating_mul(u128::from(self.ack_rate_numerator.max(1)));
        u64::try_from(numerator / denominator)
            .unwrap_or(u64::MAX)
            .max(self.control.mtu.load(Ordering::Relaxed))
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.smoothed_rtt = rtt.get();
        self.record(now, 1, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // The quinn-proto 0.11 Controller only reports lost bytes; approximate
        // the packet count with the current MTU (at least one packet).
        let lost_packets = lost_bytes / self.control.mtu.load(Ordering::Relaxed).max(1);
        if lost_packets > 0 {
            self.record(now, 0, lost_packets);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.control.mtu.store(u64::from(new_mtu), Ordering::Relaxed);
    }

    fn window(&self) -> u64 {
        self.target_window()
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        let pacing_bytes_per_second = u128::from(self.control.bandwidth.load(Ordering::Acquire))
            .saturating_mul(u128::from(self.ack_rate_denominator))
            / u128::from(self.ack_rate_numerator.max(1));
        metrics.pacing_rate = Some(
            u64::try_from(pacing_bytes_per_second)
                .unwrap_or(u64::MAX)
                .saturating_mul(8),
        );
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brutal_window_tracks_bdp() {
        let control = Arc::new(BrutalControl {
            enabled: AtomicBool::new(true),
            bandwidth: AtomicU64::new(1_000_000),
            mtu: AtomicU64::new(1200),
        });
        let mut brutal = Brutal::new(control, Instant::now(), 1200);
        assert_eq!(brutal.window(), INITIAL_WINDOW);
        brutal.smoothed_rtt = Duration::from_millis(100);
        // 1 MB/s * 100ms * 2 = 200 KB
        assert_eq!(brutal.window(), 200_000);
    }

    #[test]
    fn brutal_never_below_one_mtu() {
        let control = Arc::new(BrutalControl {
            enabled: AtomicBool::new(true),
            bandwidth: AtomicU64::new(1),
            mtu: AtomicU64::new(1200),
        });
        let mut brutal = Brutal::new(control, Instant::now(), 1200);
        brutal.smoothed_rtt = Duration::from_nanos(1);
        assert_eq!(brutal.window(), 1200);
    }

    #[test]
    fn factory_builds_all_kinds() {
        for kind in [CongestionKind::Bbr, CongestionKind::Cubic, CongestionKind::Brutal(1_000_000)] {
            let cfg = Arc::new(CongestionConfig::new(kind));
            let mut c = cfg.build(Instant::now(), 1200);
            assert!(c.initial_window() > 0);
            assert!(c.window() > 0);
            c.on_mtu_update(1400);
            c.on_congestion_event(Instant::now(), Instant::now(), false, 2400);
        }
    }
}
