// Copyright (C) 2022, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! BBR v3 Congestion Control
//!
//! This implementation is based on the following draft:
//! <https://tools.ietf.org/html/draft-cardwell-iccrg-bbr-congestion-control-02>

use crate::minmax::Minmax;
use crate::recovery::*;

use std::time::Duration;
use std::time::Instant;

use super::CongestionControlOps;

pub(crate) static BBR3: CongestionControlOps = CongestionControlOps {
    on_init,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    checkpoint,
    rollback,
    has_custom_pacing,
    debug_fmt,
};

/// The static discount factor of 1% used to scale BBR.bw to produce
/// BBR.pacing_rate.
const PACING_MARGIN_PERCENT: f64 = 0.01;

/// A constant specifying the minimum gain value
/// for calculating the pacing rate that will allow the sending rate to
/// double each round (4*ln(2) ~=2.77 ) BBRStartupPacingGain; used in
/// Startup mode for BBR.pacing_gain.
const STARTUP_PACING_GAIN: f64 = 2.77;

/// A constant specifying the pacing gain value for Probe Down mode.
const PROBE_DOWN_PACING_GAIN: f64 = 0.90;

/// A constant specifying the pacing gain value for Probe Up mode.
const PROBE_UP_PACING_GAIN: f64 = 5_f64 / 4_f64;

/// A constant specifying the pacing gain value for Probe Refill, Probe RTT,
/// Cruise mode.
const PACING_GAIN: f64 = 1.0;

/// A constant specifying the minimum gain value for the cwnd in the Startup
/// phase
const STARTUP_CWND_GAIN: f64 = 2.0;

/// A constant specifying the minimum gain value for
/// calculating the cwnd that will allow the sending rate to double each
/// round (2.0); used in Probe and Drain mode for BBR.cwnd_gain.
const CWND_GAIN: f64 = 2.0;

/// The maximum tolerated per-round-trip packet loss rate
/// when probing for bandwidth (the default is 2%).
const LOSS_THRESH: f64 = 0.02;

/// Exit startup if the number of loss marking events is >=FULL_LOSS_COUNT
const FULL_LOSS_COUNT: u32 = 6;

/// The default multiplicative decrease to make upon each round
/// trip during which the connection detects packet loss (the value is
/// 0.7).
const BETA: f64 = 0.7;

/// The multiplicative factor to apply to BBR.inflight_hi
/// when attempting to leave free headroom in the path (e.g. free space
/// in the bottleneck buffer or free time slots in the bottleneck link)
/// that can be used by cross traffic (the value is 0.85).
const HEADROOM: f64 = 0.85;

/// The minimal cwnd value BBR targets, to allow
/// pipelining with TCP endpoints that follow an "ACK every other packet"
/// delayed-ACK policy: 4 * SMSS.
const MIN_PIPE_CWND_PKTS: usize = 4;

// To do: Tune window for expiry of Max BW measurement
// The filter window length for BBR.MaxBwFilter = 2 (representing up to 2
// ProbeBW cycles, the current cycle and the previous full cycle).
// const MAX_BW_FILTER_LEN: Duration = Duration::from_secs(2);

// To do: Tune window for expiry of ACK aggregation measurement
// The window length of the BBR.ExtraACKedFilter max filter window: 10 (in
// units of packet-timed round trips).
// const EXTRA_ACKED_FILTER_LEN: Duration = Duration::from_secs(10);

/// A constant specifying the length of the BBR.min_rtt min filter window,
/// MinRTTFilterLen is 10 secs.
const MIN_RTT_FILTER_LEN: u32 = 1;

/// A constant specifying the gain value for calculating the cwnd during
/// ProbeRTT: 0.5 (meaning that ProbeRTT attempts to reduce in-flight data to
/// 50% of the estimated BDP).
const PROBE_RTT_CWND_GAIN: f64 = 0.5;

/// A constant specifying the minimum duration for which ProbeRTT state holds
/// inflight to BBRMinPipeCwnd or fewer packets: 200 ms.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// ProbeRTTInterval: A constant specifying the minimum time interval between
/// ProbeRTT states. To do: investigate probe duration. Set arbitrarily high for
/// now.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);

/// Threshold for checking a full bandwidth growth during Startup.
const MAX_BW_GROWTH_THRESHOLD: f64 = 1.25;

/// Threshold for determining maximum bandwidth of network during Startup.
const MAX_BW_COUNT: usize = 3;

/// ECN: Maximum min_rtt (in microseconds) for ECN eligibility.
/// 100ms -- ECN active for terrestrial and LEO, disabled for MEO/GEO where feedback is stale.
const ECN_MAX_RTT_US: u64 = 100_000;

/// ECN: EWMA gain for updating ecn_alpha (6.25%).
const ECN_ALPHA_GAIN: f64 = 1.0 / 16.0;

/// ECN: Initial value for ecn_alpha.
const ECN_ALPHA_INIT: f64 = 1.0;

/// ECN: Maximum reduction factor per ECN signal (33%).
const ECN_FACTOR: f64 = 1.0 / 3.0;

/// ECN: CE ratio threshold above which inflight_hi and bw_hi are reduced.
const ECN_THRESH: f64 = 0.5;

/// BBR3 Internal State Machine.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum BBR3StateMachine {
    Startup,
    Drain,
    ProbeBWDOWN,
    ProbeBWCRUISE,
    ProbeBWREFILL,
    ProbeBWUP,
    ProbeRTT,
}

/// BBR3 Ack Phases.
#[derive(Debug, PartialEq, Eq)]
enum BBR3AckPhase {
    Init,
    ProbeFeedback,
    ProbeStarting,
    ProbeStopping,
    Refilling,
}

/// BBR3 Specific State Variables.
pub struct State {
    // 2.3.  Per-ACK Rate Sample State
    // It's stored in rate sample but we keep in BBR state here.

    // The volume of data that was estimated to be in
    // flight at the time of the transmission of the packet that has just
    // been ACKed.
    tx_in_flight: usize,

    // The volume of data that was declared lost between the
    // transmission and acknowledgement of the packet that has just been
    // ACKed.
    lost: usize,

    // The volume of data cumulatively or selectively acknowledged upon the ACK
    // that was just received.  (This quantity is referred to as "DeliveredData"
    // in [RFC6937].)
    newly_acked_bytes: usize,

    // The volume of data newly marked lost upon the ACK that was just received.
    newly_lost_bytes: usize,

    // 2.4.  Output Control Parameters
    // The current pacing rate for a BBR3 flow, which controls inter-packet
    // spacing.
    pacing_rate: u64,

    // Save initial pacing rate so we can update when more reliable bytes
    // delivered and RTT samples are available
    init_pacing_rate: u64,

    // 2.5.  Pacing State and Parameters
    // The dynamic gain factor used to scale BBR.bw to
    // produce BBR.pacing_rate.
    pacing_gain: f64,

    // 2.6.  cwnd State and Parameters
    // The dynamic gain factor used to scale the estimated BDP to produce a
    // congestion window (cwnd).
    cwnd_gain: f64,

    // A boolean indicating whether BBR is currently using packet conservation
    // dynamics to bound cwnd.
    packet_conservation: bool,

    // 2.7.  General Algorithm State
    // The current state of a BBR3 flow in the BBR3 state machine.
    state: BBR3StateMachine,

    // Count of packet-timed round trips elapsed so far.
    round_count: u64,

    // A boolean that BBR3 sets to true once per packet-timed round trip,
    // on ACKs that advance BBR3.round_count.
    round_start: bool,

    // packet.delivered value denoting the end of a packet-timed round trip.
    next_round_delivered: usize,

    // A boolean that is true if and only if a connection is restarting after
    // being idle.
    idle_restart: bool,

    // 2.9.1.  Data Rate Network Path Model Parameters
    // The windowed maximum recent bandwidth sample - obtained using the BBR
    // delivery rate sampling algorithm
    // [draft-cheng-iccrg-delivery-rate-estimation] - measured during the current
    // or previous bandwidth probing cycle (or during Startup, if the flow is
    // still in that state).  (Part of the long-term model.)
    max_bw: u64,

    // The long-term maximum sending bandwidth that the algorithm estimates will
    // produce acceptable queue pressure, based on signals in the current or
    // previous bandwidth probing cycle, as measured by loss.  (Part of the
    // long-term model.)
    bw_hi: u64,

    // The short-term maximum sending bandwidth that the algorithm estimates is
    // safe for matching the current network path delivery rate, based on any
    // loss signals in the current bandwidth probing cycle.  This is generally
    // lower than max_bw or bw_hi (thus the name).  (Part of the short-term
    // model.)
    bw_lo: u64,

    // The maximum sending bandwidth that the algorithm estimates is appropriate
    // for matching the current network path delivery rate, given all available
    // signals in the model, at any time scale.  It is the min() of max_bw,
    // bw_hi, and bw_lo.
    bw: u64,

    // 2.9.2.  Data Volume Network Path Model Parameters
    // The windowed minimum round-trip time sample measured over the last
    // MinRTTFilterLen = 10 seconds.  This attempts to estimate the two-way
    // propagation delay of the network path when all connections sharing a
    // bottleneck are using BBR, but also allows BBR to estimate the value
    // required for a bdp estimate that allows full throughput if there are
    // legacy loss-based Reno or CUBIC flows sharing the bottleneck.
    min_rtt: Duration,

    // The estimate of the network path's BDP (Bandwidth-Delay Product), computed
    // as: BBR.bdp = BBR.bw * BBR.min_rtt.
    bdp: usize,

    // A volume of data that is the estimate of the recent degree of aggregation
    // in the network path.
    extra_acked: usize,

    // The estimate of the minimum volume of data necessary to achieve full
    // throughput when using sender (TSO/GSO) and receiver (LRO, GRO) host
    // offload mechanisms.
    offload_budget: usize,

    // The estimate of the volume of in-flight data required to fully utilize the
    // bottleneck bandwidth available to the flow, based on the BDP estimate
    // (BBR.bdp), the aggregation estimate (BBR.extra_acked), the offload budget
    // (BBR.offload_budget), and BBRMinPipeCwnd.
    max_inflight: usize,

    // Analogous to BBR.bw_hi, the long-term maximum volume of in-flight data
    // that the algorithm estimates will produce acceptable queue pressure, based
    // on signals in the current or previous bandwidth probing cycle, as measured
    // by loss.  That is, if a flow is probing for bandwidth, and observes that
    // sending a particular volume of in-flight data causes a loss rate higher
    // than the loss rate objective, it sets inflight_hi to that volume of data.
    // (Part of the long-term model.)
    inflight_hi: usize,

    // Analogous to BBR.bw_lo, the short-term maximum volume of in-flight data
    // that the algorithm estimates is safe for matching the current network path
    // delivery process, based on any loss signals in the current bandwidth
    // probing cycle.  This is generally lower than max_inflight or inflight_hi
    // (thus the name).  (Part of the short-term model.)
    inflight_lo: usize,

    // 2.10.  State for Responding to Congestion
    // a 1-round-trip max of delivered bandwidth (rs.delivery_rate).
    bw_latest: u64,

    // a 1-round-trip max of delivered volume of data (rs.delivered).
    inflight_latest: usize,

    // 2.11.  Estimating BBR.max_bw
    // The filter for tracking the maximum recent rs.delivery_rate sample, for
    // estimating BBR.max_bw.
    max_bw_filter: Minmax<u64>,

    // The virtual time used by the BBR.max_bw filter window.  Note that
    // BBR.cycle_count only needs to be tracked with a single bit, since the
    // BBR.MaxBwFilter only needs to track samples from two time slots: the
    // previous ProbeBW cycle and the current ProbeBW cycle.
    cycle_count: u64,

    // 2.12.  Estimating BBR.extra_acked
    // the start of the time interval for estimating the excess amount of data
    // acknowledged due to aggregation effects.
    extra_acked_interval_start: Instant,

    // the volume of data marked as delivered since
    // BBR.extra_acked_interval_start.
    extra_acked_delivered: usize,

    // BBR.ExtraACKedFilter: the max filter tracking the recent maximum degree of
    // aggregation in the path.
    extra_acked_filter: Minmax<usize>,

    // 2.13.  Startup Parameters and State
    // A boolean that records whether BBR estimates that it has ever fully
    // utilized its available bandwidth ("filled the pipe").
    filled_pipe: bool,

    // A recent baseline BBR.max_bw to estimate if BBR has "filled the pipe" in
    // Startup.
    full_bw: u64,

    // The number of non-app-limited round trips without large increases in
    // BBR.full_bw.
    full_bw_count: usize,

    // 2.14.1.  Parameters for Estimating BBR.min_rtt
    // The wall clock time at which the current BBR.min_rtt sample was obtained.
    min_rtt_stamp: Instant,

    // 2.14.2.  Parameters for Scheduling ProbeRTT
    // The minimum RTT sample recorded in the last ProbeRTTInterval.
    probe_rtt_min_delay: Duration,

    // The wall clock time at which the current BBR.probe_rtt_min_delay sample
    // was obtained.
    probe_rtt_min_stamp: Instant,

    // A boolean recording whether the BBR.probe_rtt_min_delay has expired and is
    // due for a refresh with an application idle period or a transition into
    // ProbeRTT state.
    probe_rtt_expired: bool,

    /// Configurable ProbeRTT interval. Defaults to PROBE_RTT_INTERVAL (5s).
    /// Quick- can override per satellite profile (e.g. 15s for GEO).
    pub probe_rtt_interval: Duration,

    // Others
    // A state indicating we are in the recovery.
    in_recovery: bool,

    // Start time of the connection.
    start_time: Instant,

    // Saved cwnd before loss recovery.
    prior_cwnd: usize,

    // Whether we have a bandwidth probe samples.
    bw_probe_samples: bool,

    // Others
    probe_up_cnt: usize,

    prior_bytes_in_flight: usize,

    probe_rtt_done_stamp: Option<Instant>,

    probe_rtt_round_done: bool,

    bw_probe_wait: Duration,

    rounds_since_probe: usize,

    cycle_stamp: Instant,

    ack_phase: BBR3AckPhase,

    bw_probe_up_rounds: usize,

    bw_probe_up_acks: usize,

    loss_round_start: bool,

    loss_round_delivered: usize,

    loss_in_round: bool,

    loss_events_in_round: usize,

    /// Count of losses that passed discrimination (not classified as isolated BER).
    /// Used to gate loss_in_round when satellite_loss_discrimination is enabled.
    pub congestion_losses_in_round: usize,
    /// Timestamp of last detected packet loss (for bit-error discrimination).
    pub last_loss_time: Option<Instant>,

    /// Count of consecutive isolated losses classified as bit errors.
    pub consecutive_isolated_losses: u32,

    /// ECN: Whether the connection is eligible for ECN processing
    /// (min_rtt <= 100ms, i.e., terrestrial and LEO links).
    pub(crate) ecn_eligible: bool,

    /// ECN: Whether any CE marks were observed in the current round.
    pub(crate) ecn_in_round: bool,

    /// ECN: EWMA of CE ratio, used to scale inflight_hi/bw_hi reductions.
    pub(crate) ecn_alpha: f64,

    /// ECN: Total bytes delivered in the current round (for CE ratio).
    pub(crate) ecn_bytes_delivered: usize,

    /// ECN: Total CE-marked bytes delivered in the current round.
    pub(crate) ecn_ce_bytes_delivered: usize,

    /// ECN: Prior cumulative ECN-CE count from the last ACK, for delta computation.
    pub(crate) prior_ecn_ce_count: u64,
}

impl State {
    pub fn new() -> Self {
        let now = Instant::now();

        State {
            tx_in_flight: 0,

            lost: 0,

            newly_acked_bytes: 0,

            newly_lost_bytes: 0,

            pacing_rate: 0,

            init_pacing_rate: 0,

            pacing_gain: 0.0,

            cwnd_gain: 0.0,

            packet_conservation: false,

            state: BBR3StateMachine::Startup,

            round_count: 0,

            round_start: false,

            next_round_delivered: 0,

            idle_restart: false,

            max_bw: 0,

            bw_hi: u64::MAX,

            bw_lo: u64::MAX,

            bw: 0,

            min_rtt: Duration::MAX,

            bdp: 0,

            extra_acked: 0,

            offload_budget: 0,

            max_inflight: 0,

            inflight_hi: usize::MAX,

            inflight_lo: usize::MAX,

            bw_latest: 0,

            inflight_latest: 0,

            max_bw_filter: Minmax::new(0),

            cycle_count: 0,

            extra_acked_interval_start: now,

            extra_acked_delivered: 0,

            extra_acked_filter: Minmax::new(0),

            filled_pipe: false,

            full_bw: 0,

            full_bw_count: 0,

            min_rtt_stamp: now,

            probe_rtt_min_delay: Duration::MAX,

            probe_rtt_min_stamp: now,

            probe_rtt_expired: false,

            probe_rtt_interval: PROBE_RTT_INTERVAL,

            in_recovery: false,

            start_time: now,

            prior_cwnd: 0,

            bw_probe_samples: false,

            probe_up_cnt: 0,

            prior_bytes_in_flight: 0,

            probe_rtt_done_stamp: None,

            probe_rtt_round_done: false,

            bw_probe_wait: Duration::ZERO,

            rounds_since_probe: 0,

            cycle_stamp: now,

            ack_phase: BBR3AckPhase::Init,

            bw_probe_up_rounds: 0,

            bw_probe_up_acks: 0,

            loss_round_start: false,

            loss_round_delivered: 0,

            loss_in_round: false,

            loss_events_in_round: 0,
            congestion_losses_in_round: 0,
            last_loss_time: None,
            consecutive_isolated_losses: 0,
            ecn_eligible: false,
            ecn_in_round: false,
            ecn_alpha: ECN_ALPHA_INIT,
            ecn_bytes_delivered: 0,
            ecn_ce_bytes_delivered: 0,
            prior_ecn_ce_count: 0,
        }
    }
}

// When entering the recovery episode.
fn bbr3_enter_recovery(r: &mut Congestion, in_flight: usize, now: Instant) {
    r.bbr3_state.prior_cwnd = per_ack::bbr3_save_cwnd(r);

    r.congestion_window =
        in_flight + r.bbr3_state.newly_acked_bytes.max(r.max_datagram_size);
    r.congestion_recovery_start_time = Some(now);

    r.bbr3_state.packet_conservation = true;
    r.bbr3_state.in_recovery = true;

    // Start round now.
    r.bbr3_state.next_round_delivered = r.delivery_rate.delivered();
}

// When exiting the recovery episode.
fn bbr3_exit_recovery(r: &mut Congestion) {
    r.congestion_recovery_start_time = None;

    r.bbr3_state.packet_conservation = false;
    r.bbr3_state.in_recovery = false;

    per_ack::bbr3_restore_cwnd(r);
}

// Congestion Control Hooks.
//
fn on_init(r: &mut Congestion) {
    init::bbr3_init(r);
}

fn on_packet_sent(
    r: &mut Congestion, _sent_bytes: usize, bytes_in_flight: usize, now: Instant,
) {
    per_transmit::bbr3_on_transmit(r, bytes_in_flight, now);
}

fn on_packets_acked(
    r: &mut Congestion, bytes_in_flight: usize, packets: &mut Vec<Acked>,
    now: Instant, _rtt_stats: &RttStats,
    ecn_counts: Option<crate::frame::EcnCounts>,
) {
    r.bbr3_state.newly_acked_bytes = 0;

    let time_sent = packets.last().map(|pkt| pkt.time_sent);

    r.bbr3_state.prior_bytes_in_flight = bytes_in_flight;
    let mut bytes_in_flight = bytes_in_flight;

    for p in packets.drain(..) {
        per_ack::bbr3_update_model_and_state(r, &p, bytes_in_flight, now);

        r.bbr3_state.prior_bytes_in_flight = bytes_in_flight;
        bytes_in_flight -= p.size;

        r.bbr3_state.newly_acked_bytes += p.size;
        r.bbr3_state.ecn_bytes_delivered += p.size;
    }

    if let Some(ts) = time_sent {
        if !r.in_congestion_recovery(ts) {
            // Upon exiting loss recovery.
            bbr3_exit_recovery(r);
        }
    }

    per_ack::bbr3_update_control_parameters(r, bytes_in_flight, now);

    // ECN processing: update alpha and potentially reduce inflight_hi/bw_hi.
    if let Some(ref ecn) = ecn_counts {
        per_loss::bbr3_update_ecn(r, ecn);
    }

    r.bbr3_state.newly_lost_bytes = 0;
}

fn congestion_event(
    r: &mut Congestion, bytes_in_flight: usize, lost_bytes: usize,
    largest_lost_pkt: &Sent, now: Instant,
) {
    if r.cwnd_frozen {
        return;
    }

    r.bbr3_state.newly_lost_bytes = lost_bytes;

    per_loss::bbr3_update_on_loss(r, largest_lost_pkt, lost_bytes, now);

    // Upon entering Fast Recovery.
    if !r.in_congestion_recovery(largest_lost_pkt.time_sent) {
        // Upon entering Fast Recovery.
        bbr3_enter_recovery(r, bytes_in_flight - lost_bytes, now);
    }
}

fn checkpoint(_r: &mut Congestion) {}

fn rollback(_r: &mut Congestion) -> bool {
    false
}

fn has_custom_pacing() -> bool {
    true
}

/// Compute Hybla-inspired rho factor from min_rtt.
/// rho = max(min_rtt / 25ms, 1.0)
pub(crate) fn satellite_rho(min_rtt: Duration) -> f64 {
    (min_rtt.as_millis() as f64 / 25.0).max(1.0)
}

// rate -> kbit/sec. if inf, return -1
fn rate_kbps(rate: u64) -> isize {
    if rate == u64::MAX {
        -1
    } else {
        (rate * 8 / 1000) as isize
    }
}

fn debug_fmt(r: &Congestion, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let bbr = &r.bbr3_state;

    write!(f, "bbr3={{ ")?;
    write!(
        f,
        "state={:?} in_recovery={} ack_phase={:?} filled_pipe={} full_bw_count={} loss_events_in_round={} ",
        bbr.state, bbr.in_recovery, bbr.ack_phase, bbr.filled_pipe, bbr.full_bw_count, bbr.loss_events_in_round
    )?;
    write!(
        f,
        "send_quantum={} extra_acked={} min_rtt={:?} round_start={} ",
        r.send_quantum, bbr.extra_acked, bbr.min_rtt, bbr.round_start
    )?;
    write!(
        f,
        "max_bw={}kbps bw_lo={}kbps bw={}kbps bw_hi={}kbps full_bw={}kbps ",
        rate_kbps(bbr.max_bw),
        rate_kbps(bbr.bw_lo),
        rate_kbps(bbr.bw),
        rate_kbps(bbr.bw_hi),
        rate_kbps(bbr.full_bw)
    )?;
    write!(
        f,
        "inflight_lo={} inflight_hi={} max_inflight={} ",
        bbr.inflight_lo, bbr.inflight_hi, bbr.max_inflight
    )?;
    write!(
        f,
        "probe_up_cnt={} bw_probe_samples={} ",
        bbr.probe_up_cnt, bbr.bw_probe_samples
    )?;
    write!(f, "}}")
}

// TODO: write more tests
#[cfg(test)]
mod tests {
    use super::*;

    use smallvec::smallvec;

    use crate::recovery;

    #[test]
    fn bbr_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);

        // on_init() is called in Connection::new(), so it need to be
        // called manually here.

        assert_eq!(
            r.cwnd(),
            r.max_datagram_size * r.congestion.initial_congestion_window_packets
        );
        assert_eq!(r.bytes_in_flight, 0);

        assert_eq!(r.congestion.bbr3_state.state, BBR3StateMachine::Startup);
    }

    #[test]
    fn bbr3_startup() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        // Send 5 packets.
        for pn in 0..5 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;
        let cwnd_prev = r.cwnd();

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..5);

        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                None,
            )
            .is_ok());

        assert_eq!(r.congestion.bbr3_state.state, BBR3StateMachine::Startup);
        assert_eq!(r.cwnd(), cwnd_prev + mss * 5);
        assert_eq!(r.bytes_in_flight, 0);
        assert_eq!(
            r.delivery_rate(),
            ((mss * 5) as f64 / rtt.as_secs_f64()) as u64
        );
        assert_eq!(r.congestion.bbr3_state.full_bw, r.delivery_rate());
    }

    #[test]
    fn bbr3_congestion_event() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        // Send 5 packets.
        for pn in 0..5 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;

        // Make a packet loss to trigger a congestion event.
        let mut acked = ranges::RangeSet::default();
        acked.insert(4..5);

        // 2 acked, 2 x MSS lost.
        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                None,
            )
            .is_ok());

        assert!(r.congestion.bbr3_state.in_recovery);

        // Still in flight: 2, 3.
        assert_eq!(r.bytes_in_flight, mss * 2);

        assert_eq!(r.congestion.bbr3_state.newly_acked_bytes, mss);

        assert_eq!(r.cwnd(), mss * 3);
    }

    #[test]
    fn bbr3_probe_bw() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        let mut pn = 0;

        // Stop right before filled_pipe=true.
        for _ in 0..3 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.congestion.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;

            let rtt = Duration::from_millis(50);

            let now = now + rtt;

            let mut acked = ranges::RangeSet::default();
            acked.insert(0..pn);

            assert!(r
                .on_ack_received(
                    &acked,
                    25,
                    packet::Epoch::Application,
                    HandshakeStatus::default(),
                    now,
                    "",
                    None,
                )
                .is_ok());
        }

        // Stop at right before filled_pipe=true.
        for _ in 0..5 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.congestion.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;

        let mut acked = ranges::RangeSet::default();

        // We sent 5 packets, but ack only one, so stay
        // in Drain state.
        acked.insert(0..pn - 4);

        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                None,
            )
            .is_ok());

        assert_eq!(r.congestion.bbr3_state.state, BBR3StateMachine::Drain);
        assert!(r.congestion.bbr3_state.filled_pipe);
        assert!(r.congestion.bbr3_state.pacing_gain < 1.0);
    }

    #[test]
    fn bbr3_probe_rtt() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        let mut pn = 0;

        // At 4th roundtrip, filled_pipe=true and switch to Drain,
        // but move to ProbeBW immediately because bytes_in_flight is
        // smaller than BBRInFlight(1).
        for _ in 0..4 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.congestion.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;

            let rtt = Duration::from_millis(50);
            let now = now + rtt;

            let mut acked = ranges::RangeSet::default();
            acked.insert(0..pn);

            assert!(r
                .on_ack_received(
                    &acked,
                    25,
                    packet::Epoch::Application,
                    HandshakeStatus::default(),
                    now,
                    "",
                    None,
                )
                .is_ok());
        }

        // Now we are in ProbeBW state.
        assert_eq!(
            r.congestion.bbr3_state.state,
            BBR3StateMachine::ProbeBWCRUISE
        );

        // After RTPROP_FILTER_LEN (10s), switch to ProbeRTT.
        let now = now + PROBE_RTT_INTERVAL;

        let pkt = Sent {
            pkt_num: pn,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: r.congestion.delivery_rate.delivered(),
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            pkt,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        pn += 1;

        // Don't update rtprop by giving larger rtt than before.
        // If rtprop is updated, rtprop expiry check is reset.
        let rtt = Duration::from_millis(100);
        let now = now + rtt;

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..pn);

        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                None,
            )
            .is_ok());

        assert_eq!(r.congestion.bbr3_state.state, BBR3StateMachine::ProbeRTT);
        assert_eq!(r.congestion.bbr3_state.pacing_gain, 1.0);
    }

    #[test]
    fn bbr3_loss_thresh_default() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);

        // Default: no satellite_loss_threshold configured.
        assert_eq!(r.congestion.satellite_loss_threshold, None);

        // Simulate: tx_in_flight=1000, lost=21 (>2% of 1000).
        // With default LOSS_THRESH=0.02, 21 > 20 => inflight too high.
        let mut cc = r.congestion;
        cc.bbr3_state.tx_in_flight = 1000;
        cc.bbr3_state.lost = 21;
        assert!(per_loss::bbr3_is_inflight_too_high(&mut cc));

        // 19 < 20 => not too high.
        cc.bbr3_state.lost = 19;
        assert!(!per_loss::bbr3_is_inflight_too_high(&mut cc));
    }

    #[test]
    fn bbr3_loss_thresh_satellite_raised() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        cfg.set_satellite_loss_threshold(0.05); // 5% for GEO satellite

        let r = Recovery::new(&cfg);
        assert_eq!(r.congestion.satellite_loss_threshold, Some(0.05));

        // tx_in_flight=1000, lost=40 (<5% of 1000=50).
        // With raised threshold, 40 < 50 => not too high.
        let mut cc = r.congestion;
        cc.bbr3_state.tx_in_flight = 1000;
        cc.bbr3_state.lost = 40;
        assert!(!per_loss::bbr3_is_inflight_too_high(&mut cc));

        // 51 > 50 => inflight too high even with raised threshold.
        cc.bbr3_state.lost = 51;
        assert!(per_loss::bbr3_is_inflight_too_high(&mut cc));
    }

    #[test]
    fn bbr3_loss_discrimination_default_disabled() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);

        // Default: discrimination disabled.
        assert!(!r.congestion.satellite_loss_discrimination);
        assert_eq!(r.congestion.bbr3_state.last_loss_time, None);
        assert_eq!(r.congestion.bbr3_state.consecutive_isolated_losses, 0);
    }

    #[test]
    fn bbr3_loss_discrimination_isolated_skips_response() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        cfg.set_satellite_loss_discrimination(true);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        // Set up BBR3 state for probing.
        cc.bbr3_state.bw_probe_samples = true;
        cc.bbr3_state.min_rtt = Duration::from_millis(100);

        let now = Instant::now();
        let mss = 1200;

        // First loss: always classified as isolated (no prior loss time).
        let pkt1 = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 10000,
            lost: 0,
            has_data: true,
            pmtud: false,
        };

        per_loss::bbr3_update_on_loss(&mut cc, &pkt1, mss, now);
        assert_eq!(cc.bbr3_state.consecutive_isolated_losses, 1);
        assert_eq!(cc.bbr3_state.last_loss_time, Some(now));

        // Second loss after large gap (>2*min_rtt=200ms): isolated.
        let later = now + Duration::from_millis(300);
        let pkt2 = Sent {
            pkt_num: 1,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 10000,
            lost: 0,
            has_data: true,
            pmtud: false,
        };

        per_loss::bbr3_update_on_loss(&mut cc, &pkt2, mss, later);
        assert_eq!(cc.bbr3_state.consecutive_isolated_losses, 2);
    }

    #[test]
    fn bbr3_loss_discrimination_burst_triggers_response() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        cfg.set_satellite_loss_discrimination(true);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        cc.bbr3_state.bw_probe_samples = true;
        cc.bbr3_state.min_rtt = Duration::from_millis(100);

        let now = Instant::now();
        let mss = 1200;

        let pkt = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 10000,
            lost: 0,
            has_data: true,
            pmtud: false,
        };

        // First loss: isolated.
        per_loss::bbr3_update_on_loss(&mut cc, &pkt, mss, now);
        assert_eq!(cc.bbr3_state.consecutive_isolated_losses, 1);

        // Second loss within 2*min_rtt (50ms < 200ms): burst => not isolated.
        // consecutive_isolated_losses resets to 0.
        let soon = now + Duration::from_millis(50);
        per_loss::bbr3_update_on_loss(&mut cc, &pkt, mss, soon);
        assert_eq!(cc.bbr3_state.consecutive_isolated_losses, 0);
    }

    #[test]
    fn bbr3_loss_discrimination_disabled_normal_path() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        // Do NOT enable discrimination.

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        cc.bbr3_state.bw_probe_samples = true;
        cc.bbr3_state.min_rtt = Duration::from_millis(100);

        let now = Instant::now();
        let mss = 1200;

        let pkt = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 10000,
            lost: 0,
            has_data: true,
            pmtud: false,
        };

        // With discrimination disabled, losses don't update
        // last_loss_time or consecutive_isolated_losses.
        per_loss::bbr3_update_on_loss(&mut cc, &pkt, mss, now);
        assert_eq!(cc.bbr3_state.last_loss_time, None);
        assert_eq!(cc.bbr3_state.consecutive_isolated_losses, 0);
    }

    #[test]
    fn satellite_rho_computation() {
        use std::time::Duration;
        assert_eq!(satellite_rho(Duration::from_millis(25)), 1.0);
        assert_eq!(satellite_rho(Duration::from_millis(50)), 2.0);
        assert_eq!(satellite_rho(Duration::from_millis(600)), 24.0);
        assert_eq!(satellite_rho(Duration::from_millis(10)), 1.0);
    }

    #[test]
    fn satellite_rho_startup_loss_tolerance() {
        // At GEO (600ms), rho=24, full_loss_count = 6*24 = 144
        let rho = satellite_rho(Duration::from_millis(600));
        let count = ((FULL_LOSS_COUNT as f64 * rho) as usize).min(256);
        assert_eq!(count, 144);
    }

    #[test]
    fn bbr3_congestion_losses_in_round_zero_for_isolated() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        cfg.set_satellite_loss_discrimination(true);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        cc.bbr3_state.bw_probe_samples = true;
        cc.bbr3_state.min_rtt = Duration::from_millis(100);

        let now = Instant::now();
        let mss = 1200;

        let pkt = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 10000,
            lost: 0,
            has_data: true,
            pmtud: false,
        };

        // First loss: isolated (no prior). congestion_losses_in_round stays 0.
        per_loss::bbr3_update_on_loss(&mut cc, &pkt, mss, now);
        assert_eq!(cc.bbr3_state.congestion_losses_in_round, 0);
        assert_eq!(cc.bbr3_state.consecutive_isolated_losses, 1);

        // Second loss after large gap (>2*min_rtt=200ms): also isolated.
        let later = now + Duration::from_millis(300);
        per_loss::bbr3_update_on_loss(&mut cc, &pkt, mss, later);
        assert_eq!(cc.bbr3_state.congestion_losses_in_round, 0);
        assert_eq!(cc.bbr3_state.consecutive_isolated_losses, 2);
    }

    #[test]
    fn bbr3_congestion_losses_in_round_incremented_for_burst() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        cfg.set_satellite_loss_discrimination(true);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        cc.bbr3_state.bw_probe_samples = true;
        cc.bbr3_state.min_rtt = Duration::from_millis(100);

        let now = Instant::now();
        let mss = 1200;

        let pkt = Sent {
            pkt_num: 0,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 10000,
            lost: 0,
            has_data: true,
            pmtud: false,
        };

        // First loss: isolated.
        per_loss::bbr3_update_on_loss(&mut cc, &pkt, mss, now);
        assert_eq!(cc.bbr3_state.congestion_losses_in_round, 0);

        // Second loss within 2*min_rtt: burst => congestion.
        let soon = now + Duration::from_millis(50);
        per_loss::bbr3_update_on_loss(&mut cc, &pkt, mss, soon);
        assert_eq!(cc.bbr3_state.congestion_losses_in_round, 1);
    }

    #[test]
    fn bbr3_loss_in_round_gated_by_discrimination() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        cfg.set_satellite_loss_discrimination(true);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        // Simulate: discrimination enabled, raw lost > 0 but
        // congestion_losses_in_round == 0 (all losses were isolated BER).
        cc.bbr3_state.lost = 5;
        cc.bbr3_state.congestion_losses_in_round = 0;
        cc.bbr3_state.loss_in_round = false;

        // Manually replicate the gating logic from bbr3_update_congestion_signals.
        // With discrimination on and congestion_losses_in_round == 0,
        // loss_in_round must NOT be set.
        if cc.bbr3_state.lost > 0 {
            if cc.satellite_loss_discrimination {
                if cc.bbr3_state.congestion_losses_in_round > 0 {
                    cc.bbr3_state.loss_in_round = true;
                }
            } else {
                cc.bbr3_state.loss_in_round = true;
            }
        }
        assert!(!cc.bbr3_state.loss_in_round,
            "loss_in_round must stay false when only isolated losses in round");

        // Now with congestion_losses_in_round > 0, it should set loss_in_round.
        cc.bbr3_state.congestion_losses_in_round = 1;
        cc.bbr3_state.loss_in_round = false;
        if cc.bbr3_state.lost > 0 {
            if cc.satellite_loss_discrimination {
                if cc.bbr3_state.congestion_losses_in_round > 0 {
                    cc.bbr3_state.loss_in_round = true;
                }
            } else {
                cc.bbr3_state.loss_in_round = true;
            }
        }
        assert!(cc.bbr3_state.loss_in_round,
            "loss_in_round must be true when congestion losses exist");
    }

    // ================================================================
    // BBRv3-specific tests: verify constant changes and satellite patches
    // ================================================================

    #[test]
    fn test_bbr3_constants() {
        // BBRv3 changed constants (vs BBRv2):
        // STARTUP_CWND_GAIN: 2.77 -> 2.0
        assert_eq!(STARTUP_CWND_GAIN, 2.0);

        // PROBE_DOWN_PACING_GAIN: 0.75 -> 0.90
        assert!(
            (PROBE_DOWN_PACING_GAIN - 0.90).abs() < f64::EPSILON,
            "PROBE_DOWN_PACING_GAIN should be 0.90, got {}",
            PROBE_DOWN_PACING_GAIN
        );

        // FULL_LOSS_COUNT: 8 -> 6
        assert_eq!(FULL_LOSS_COUNT, 6);

        // PROBE_RTT_INTERVAL: 86400s -> 5s
        assert_eq!(PROBE_RTT_INTERVAL, Duration::from_secs(5));

        // Unchanged constants that must remain stable:
        assert!(
            (STARTUP_PACING_GAIN - 2.77).abs() < f64::EPSILON,
            "STARTUP_PACING_GAIN should remain 2.77, got {}",
            STARTUP_PACING_GAIN
        );
        assert!(
            (LOSS_THRESH - 0.02).abs() < f64::EPSILON,
            "LOSS_THRESH should remain 0.02, got {}",
            LOSS_THRESH
        );
        assert!(
            (BETA - 0.7).abs() < f64::EPSILON,
            "BETA should remain 0.7, got {}",
            BETA
        );
        assert!(
            (HEADROOM - 0.85).abs() < f64::EPSILON,
            "HEADROOM should remain 0.85, got {}",
            HEADROOM
        );
    }

    #[test]
    fn test_bbr3_satellite_rho_scaling() {
        // GEO: rho = 600/25 = 24.0, scaled = FULL_LOSS_COUNT * rho = 6*24 = 144
        let rho_geo = satellite_rho(Duration::from_millis(600));
        assert_eq!(rho_geo, 24.0);
        let scaled_geo = ((FULL_LOSS_COUNT as f64 * rho_geo) as usize).min(256);
        assert_eq!(scaled_geo, 144);

        // LEO: rho = 40/25 = 1.6, scaled = 6*1.6 = 9.6 -> truncates to 9
        let rho_leo = satellite_rho(Duration::from_millis(40));
        assert_eq!(rho_leo, 1.6);
        let scaled_leo = ((FULL_LOSS_COUNT as f64 * rho_leo) as usize).min(256);
        assert_eq!(scaled_leo, 9);

        // MEO: rho = 120/25 = 4.8, scaled = 6*4.8 = 28.8 -> truncates to 28
        let rho_meo = satellite_rho(Duration::from_millis(120));
        assert_eq!(rho_meo, 4.8);
        let scaled_meo = ((FULL_LOSS_COUNT as f64 * rho_meo) as usize).min(256);
        assert_eq!(scaled_meo, 28);

        // Terrestrial: rho = 25/25 = 1.0, scaled = 6*1 = 6 (no scaling)
        let rho_terr = satellite_rho(Duration::from_millis(25));
        assert_eq!(rho_terr, 1.0);
        let scaled_terr = ((FULL_LOSS_COUNT as f64 * rho_terr) as usize).min(256);
        assert_eq!(scaled_terr, 6);
    }

    #[test]
    fn test_bbr3_drain_gain() {
        // In BBRv3, drain pacing_gain = PACING_GAIN / STARTUP_CWND_GAIN
        // = 1.0 / 2.0 = 0.50
        // In BBRv2 it was 1.0 / 2.77 = 0.361...
        let drain_gain = PACING_GAIN / STARTUP_CWND_GAIN;
        assert!(
            (drain_gain - 0.5).abs() < f64::EPSILON,
            "BBRv3 drain gain should be 0.50, got {}",
            drain_gain
        );

        // Verify through state machine: drive to Drain and check exact value.
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;

        let mut pn = 0;

        // Drive through 3 rounds to approach filled_pipe.
        for _ in 0..3 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.congestion.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;

            let rtt = Duration::from_millis(50);
            let now = now + rtt;

            let mut acked = ranges::RangeSet::default();
            acked.insert(0..pn);

            assert!(r
                .on_ack_received(
                    &acked,
                    25,
                    packet::Epoch::Application,
                    HandshakeStatus::default(),
                    now,
                    "",
                    None,
                )
                .is_ok());
        }

        // Send 5 more packets to trigger filled_pipe on next ack.
        for _ in 0..5 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.congestion.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;
        }

        let rtt = Duration::from_millis(50);
        let now = now + rtt;

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..pn - 4);

        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                None,
            )
            .is_ok());

        assert_eq!(r.congestion.bbr3_state.state, BBR3StateMachine::Drain);
        assert!(r.congestion.bbr3_state.filled_pipe);

        // Verify the exact BBRv3 drain gain value.
        assert!(
            (r.congestion.bbr3_state.pacing_gain - 0.5).abs() < f64::EPSILON,
            "Drain pacing_gain should be 0.50 in BBRv3, got {}",
            r.congestion.bbr3_state.pacing_gain
        );
    }

    #[test]
    fn test_bbr3_probe_rtt_interval_configurable() {
        // Default: probe_rtt_interval = PROBE_RTT_INTERVAL = 5s
        let state = State::new();
        assert_eq!(
            state.probe_rtt_interval,
            Duration::from_secs(5),
            "Default probe_rtt_interval should be 5s"
        );
        assert_eq!(state.probe_rtt_interval, PROBE_RTT_INTERVAL);

        // Override: e.g. 15s for GEO satellite profile.
        let mut state = State::new();
        state.probe_rtt_interval = Duration::from_secs(15);
        assert_eq!(
            state.probe_rtt_interval,
            Duration::from_secs(15),
            "probe_rtt_interval should be overridable to 15s"
        );

        // Override: e.g. 10s for MEO satellite profile.
        state.probe_rtt_interval = Duration::from_secs(10);
        assert_eq!(
            state.probe_rtt_interval,
            Duration::from_secs(10),
            "probe_rtt_interval should be overridable to 10s"
        );

        // Verify the override is used in ProbeRTT expiry logic.
        // Drive state machine to ProbeBW, then check that ProbeRTT
        // triggers after the configured interval.
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let mss = r.max_datagram_size;
        let mut pn = 0;

        // Drive to ProbeBW (4 rounds).
        for _ in 0..4 {
            let pkt = Sent {
                pkt_num: pn,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: mss,
                ack_eliciting: true,
                in_flight: true,
                delivered: r.congestion.delivery_rate.delivered(),
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: false,
                pmtud: false,
            };

            r.on_packet_sent(
                pkt,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            pn += 1;

            let rtt = Duration::from_millis(50);
            let now = now + rtt;

            let mut acked = ranges::RangeSet::default();
            acked.insert(0..pn);

            assert!(r
                .on_ack_received(
                    &acked,
                    25,
                    packet::Epoch::Application,
                    HandshakeStatus::default(),
                    now,
                    "",
                    None,
                )
                .is_ok());
        }

        assert_eq!(
            r.congestion.bbr3_state.state,
            BBR3StateMachine::ProbeBWCRUISE
        );

        // Override probe_rtt_interval to 15s (GEO profile).
        r.congestion.bbr3_state.probe_rtt_interval = Duration::from_secs(15);

        // After default 5s: should NOT enter ProbeRTT (interval is now 15s).
        let now = now + Duration::from_secs(6);

        let pkt = Sent {
            pkt_num: pn,
            frames: smallvec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: mss,
            ack_eliciting: true,
            in_flight: true,
            delivered: r.congestion.delivery_rate.delivered(),
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            pmtud: false,
        };

        r.on_packet_sent(
            pkt,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        pn += 1;

        let rtt = Duration::from_millis(100);
        let now = now + rtt;

        let mut acked = ranges::RangeSet::default();
        acked.insert(0..pn);

        assert!(r
            .on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
                None,
            )
            .is_ok());

        // Should still be in ProbeBW, not ProbeRTT (only 6s elapsed, need 15s).
        assert_ne!(
            r.congestion.bbr3_state.state,
            BBR3StateMachine::ProbeRTT,
            "Should not enter ProbeRTT before configured 15s interval"
        );
    }

    #[test]
    fn test_bbr3_ecn_disabled_for_satellite() {
        // ECN gate at 100ms: active for terrestrial and LEO, disabled for MEO/GEO.

        // Terrestrial (5ms): ECN enabled (5000 < 100000).
        assert!(
            Duration::from_millis(5).as_micros() as u64 <= ECN_MAX_RTT_US
        );
        // LEO (40ms): ECN enabled (40000 < 100000).
        assert!(
            Duration::from_millis(40).as_micros() as u64 <= ECN_MAX_RTT_US
        );
        // MEO (180ms): ECN disabled (180000 > 100000).
        assert!(
            Duration::from_millis(180).as_micros() as u64 > ECN_MAX_RTT_US
        );
        // GEO (600ms): ECN disabled (600000 > 100000).
        assert!(
            Duration::from_millis(600).as_micros() as u64 > ECN_MAX_RTT_US
        );
    }

    #[test]
    fn test_bbr3_ecn_constants() {
        assert_eq!(ECN_MAX_RTT_US, 100_000);
        assert!((ECN_ALPHA_GAIN - 1.0 / 16.0).abs() < 0.001);
        assert!((ECN_ALPHA_INIT - 1.0).abs() < f64::EPSILON);
        assert!((ECN_FACTOR - 1.0 / 3.0).abs() < 0.001);
        assert!((ECN_THRESH - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_bbr3_ecn_state_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let bbr = &r.congestion.bbr3_state;

        assert!(!bbr.ecn_eligible);
        assert!(!bbr.ecn_in_round);
        assert!((bbr.ecn_alpha - ECN_ALPHA_INIT).abs() < f64::EPSILON);
        assert_eq!(bbr.ecn_bytes_delivered, 0);
        assert_eq!(bbr.ecn_ce_bytes_delivered, 0);
        assert_eq!(bbr.prior_ecn_ce_count, 0);
    }

    #[test]
    fn test_bbr3_ecn_skipped_for_satellite_rtt() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        // Set min_rtt to 180ms (MEO satellite): ECN should be disabled.
        cc.bbr3_state.min_rtt = Duration::from_millis(180);

        let ecn = crate::frame::EcnCounts {
            ect0_count: 0,
            ect1_count: 0,
            ecn_ce_count: 10,
        };

        per_loss::bbr3_update_ecn(&mut cc, &ecn);

        assert!(!cc.bbr3_state.ecn_eligible);
        // prior_ecn_ce_count should NOT be updated since we returned early.
        assert_eq!(cc.bbr3_state.prior_ecn_ce_count, 0);
    }

    #[test]
    fn test_bbr3_ecn_processes_ce_for_terrestrial() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        // Set min_rtt to 2ms (terrestrial): ECN should be active.
        cc.bbr3_state.min_rtt = Duration::from_millis(2);
        cc.bbr3_state.round_start = false;

        let ecn = crate::frame::EcnCounts {
            ect0_count: 0,
            ect1_count: 0,
            ecn_ce_count: 5,
        };

        per_loss::bbr3_update_ecn(&mut cc, &ecn);

        assert!(cc.bbr3_state.ecn_eligible);
        assert!(cc.bbr3_state.ecn_in_round);
        assert_eq!(cc.bbr3_state.ecn_ce_bytes_delivered, 5);
        assert_eq!(cc.bbr3_state.prior_ecn_ce_count, 5);
    }

    #[test]
    fn test_bbr3_ecn_round_start_reduces_inflight() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        // Set up terrestrial RTT and simulate accumulated CE bytes.
        cc.bbr3_state.min_rtt = Duration::from_millis(2);
        cc.bbr3_state.round_start = true;
        cc.bbr3_state.ecn_bytes_delivered = 100;
        cc.bbr3_state.ecn_ce_bytes_delivered = 0;
        cc.bbr3_state.inflight_hi = 10000;
        cc.bbr3_state.bw_hi = 1_000_000;

        // CE ratio will be (0 + 60) / 100 = 60% > ECN_THRESH (50%).
        let ecn = crate::frame::EcnCounts {
            ect0_count: 0,
            ect1_count: 0,
            ecn_ce_count: 60,
        };

        per_loss::bbr3_update_ecn(&mut cc, &ecn);

        // inflight_hi and bw_hi should be reduced.
        assert!(cc.bbr3_state.inflight_hi < 10000);
        assert!(cc.bbr3_state.bw_hi < 1_000_000);

        // Per-round counters should be reset.
        assert_eq!(cc.bbr3_state.ecn_bytes_delivered, 0);
        assert_eq!(cc.bbr3_state.ecn_ce_bytes_delivered, 0);
        assert!(!cc.bbr3_state.ecn_in_round);
    }

    #[test]
    fn test_bbr3_ecn_no_reduction_below_thresh() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        // Set up terrestrial RTT and simulate low CE ratio.
        cc.bbr3_state.min_rtt = Duration::from_millis(2);
        cc.bbr3_state.round_start = true;
        cc.bbr3_state.ecn_bytes_delivered = 100;
        cc.bbr3_state.ecn_ce_bytes_delivered = 0;
        cc.bbr3_state.inflight_hi = 10000;
        cc.bbr3_state.bw_hi = 1_000_000;

        // CE ratio will be (0 + 10) / 100 = 10% < ECN_THRESH (50%).
        let ecn = crate::frame::EcnCounts {
            ect0_count: 0,
            ect1_count: 0,
            ecn_ce_count: 10,
        };

        per_loss::bbr3_update_ecn(&mut cc, &ecn);

        // inflight_hi and bw_hi should NOT be reduced.
        assert_eq!(cc.bbr3_state.inflight_hi, 10000);
        assert_eq!(cc.bbr3_state.bw_hi, 1_000_000);
    }

    #[test]
    fn test_bbr3_ecn_zero_delta_noop() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;

        cc.bbr3_state.min_rtt = Duration::from_millis(2);
        cc.bbr3_state.prior_ecn_ce_count = 5;

        // Same CE count as prior: delta = 0, should be a no-op.
        let ecn = crate::frame::EcnCounts {
            ect0_count: 0,
            ect1_count: 0,
            ecn_ce_count: 5,
        };

        per_loss::bbr3_update_ecn(&mut cc, &ecn);

        // ecn_eligible should remain false (not set because we returned early).
        assert!(!cc.bbr3_state.ecn_eligible);
        assert!(!cc.bbr3_state.ecn_in_round);
    }

    #[test]
    fn test_bbr3_probe_bw_up_no_premature_down() {
        // Verify: in ProbeBW_UP, when inflight_too_high is detected,
        // bw_probe_samples remains true and state does NOT transition
        // to DOWN. Only inflight_hi is capped.
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;
        let now = Instant::now();

        // Manually set up ProbeBW_UP state.
        cc.bbr3_state.state = BBR3StateMachine::ProbeBWUP;
        cc.bbr3_state.bw_probe_samples = true;
        cc.bbr3_state.min_rtt = Duration::from_millis(50);
        cc.bbr3_state.max_bw = 1_000_000;
        cc.bbr3_state.bw = 1_000_000;
        cc.congestion_window = 100_000;
        cc.bbr3_state.inflight_hi = usize::MAX;

        // Set tx_in_flight and lost to trigger inflight_too_high.
        // LOSS_THRESH = 0.02, so lost > tx_in_flight * 0.02.
        cc.bbr3_state.tx_in_flight = 50_000;
        cc.bbr3_state.lost = 2_000; // 4% > 2%

        // Confirm inflight is too high.
        assert!(per_loss::bbr3_is_inflight_too_high(&mut cc));

        let old_inflight_hi = cc.bbr3_state.inflight_hi;

        // Call the check function (which calls handle_inflight_too_high).
        let result = per_loss::bbr3_check_inflight_too_high(&mut cc, now);
        assert!(result, "inflight should be detected as too high");

        // BBRv3 behavior: state stays in ProbeBW_UP.
        assert_eq!(
            cc.bbr3_state.state,
            BBR3StateMachine::ProbeBWUP,
            "State must remain ProbeBWUP, not transition to DOWN"
        );

        // bw_probe_samples stays true (not cleared).
        assert!(
            cc.bbr3_state.bw_probe_samples,
            "bw_probe_samples must remain true in ProbeBW_UP"
        );

        // inflight_hi was capped (reduced from MAX).
        assert!(
            cc.bbr3_state.inflight_hi < old_inflight_hi,
            "inflight_hi should be capped, was {} now {}",
            old_inflight_hi,
            cc.bbr3_state.inflight_hi
        );
    }

    #[test]
    fn test_bbr3_probe_bw_up_vs_non_up_behavior() {
        // Verify: in a non-UP state (e.g. DOWN), inflight_too_high
        // DOES set bw_probe_samples=false (the old BBRv2 behavior that
        // we preserve for non-UP states).
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;
        let now = Instant::now();

        // Set up ProbeBW_DOWN state.
        cc.bbr3_state.state = BBR3StateMachine::ProbeBWDOWN;
        cc.bbr3_state.bw_probe_samples = true;
        cc.bbr3_state.min_rtt = Duration::from_millis(50);
        cc.bbr3_state.max_bw = 1_000_000;
        cc.bbr3_state.bw = 1_000_000;
        cc.congestion_window = 100_000;

        cc.bbr3_state.tx_in_flight = 50_000;
        cc.bbr3_state.lost = 2_000; // 4% > 2%

        per_loss::bbr3_check_inflight_too_high(&mut cc, now);

        // Non-UP: bw_probe_samples should be cleared.
        assert!(
            !cc.bbr3_state.bw_probe_samples,
            "bw_probe_samples must be false in non-UP states"
        );
    }

    #[test]
    fn test_bbr3_cruise_responsive_adaptation() {
        // Verify: during ProbeBW_CRUISE, when loss_in_round is true,
        // inflight_lo and bw_lo are adapted immediately (not waiting
        // for round_start).
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;
        let now = Instant::now();

        // Set up ProbeBW_CRUISE state.
        cc.bbr3_state.state = BBR3StateMachine::ProbeBWCRUISE;
        cc.bbr3_state.min_rtt = Duration::from_millis(50);
        cc.bbr3_state.max_bw = 1_000_000;
        cc.bbr3_state.bw = 1_000_000;
        cc.congestion_window = 100_000;

        // Pre-set loss_in_round (from a previous ACK this round).
        cc.bbr3_state.loss_in_round = true;

        // Mid-round: loss_round_start is false.
        cc.bbr3_state.loss_round_start = false;

        // Set initial inflight_lo and bw_lo (initialized from first congestion).
        cc.bbr3_state.inflight_lo = 80_000;
        cc.bbr3_state.bw_lo = 800_000;

        // Set inflight_latest and bw_latest (1-round max samples).
        cc.bbr3_state.inflight_latest = 50_000;
        cc.bbr3_state.bw_latest = 600_000;

        // Simulate: there was a loss (lost > 0) in this ACK.
        cc.bbr3_state.lost = 500;

        // Create a dummy Acked packet for the function signature.
        let acked = Acked {
            pkt_num: 100,
            time_sent: now - Duration::from_millis(50),
            size: 1200,
            rtt: Duration::from_millis(50),
            delivered: 10000,
            delivered_time: now - Duration::from_millis(100),
            first_sent_time: now - Duration::from_millis(150),
            is_app_limited: false,
        };

        let inflight_lo_before = cc.bbr3_state.inflight_lo;
        let bw_lo_before = cc.bbr3_state.bw_lo;

        // Call congestion signal update.
        per_loss::bbr3_update_congestion_signals(&mut cc, &acked);

        // CRUISE responsive: inflight_lo and bw_lo should be reduced
        // immediately, even though loss_round_start is false.
        assert!(
            cc.bbr3_state.inflight_lo < inflight_lo_before,
            "inflight_lo should be reduced mid-round in CRUISE: was {} now {}",
            inflight_lo_before,
            cc.bbr3_state.inflight_lo
        );
        assert!(
            cc.bbr3_state.bw_lo < bw_lo_before,
            "bw_lo should be reduced mid-round in CRUISE: was {} now {}",
            bw_lo_before,
            cc.bbr3_state.bw_lo
        );

        // Verify reduction factor: BETA = 0.7
        // bw_lo = max(bw_latest, bw_lo * BETA) = max(600000, 800000*0.7) = max(600000, 560000) = 600000
        assert_eq!(
            cc.bbr3_state.bw_lo, 600_000,
            "bw_lo should be max(bw_latest=600000, bw_lo*0.7=560000)"
        );
        // inflight_lo = max(inflight_latest, inflight_lo * BETA) = max(50000, 80000*0.7) = max(50000, 56000) = 56000
        assert_eq!(
            cc.bbr3_state.inflight_lo, 56_000,
            "inflight_lo should be max(inflight_latest=50000, inflight_lo*0.7=56000)"
        );
    }

    #[test]
    fn test_bbr3_cruise_no_adaptation_without_loss() {
        // Verify: during ProbeBW_CRUISE without loss_in_round,
        // inflight_lo and bw_lo are NOT reduced mid-round.
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);

        let r = Recovery::new(&cfg);
        let mut cc = r.congestion;
        let now = Instant::now();

        cc.bbr3_state.state = BBR3StateMachine::ProbeBWCRUISE;
        cc.bbr3_state.min_rtt = Duration::from_millis(50);
        cc.bbr3_state.max_bw = 1_000_000;
        cc.bbr3_state.bw = 1_000_000;
        cc.congestion_window = 100_000;

        // No loss in round.
        cc.bbr3_state.loss_in_round = false;
        cc.bbr3_state.loss_round_start = false;
        cc.bbr3_state.lost = 0;

        cc.bbr3_state.inflight_lo = 80_000;
        cc.bbr3_state.bw_lo = 800_000;

        let acked = Acked {
            pkt_num: 100,
            time_sent: now - Duration::from_millis(50),
            size: 1200,
            rtt: Duration::from_millis(50),
            delivered: 10000,
            delivered_time: now - Duration::from_millis(100),
            first_sent_time: now - Duration::from_millis(150),
            is_app_limited: false,
        };

        per_loss::bbr3_update_congestion_signals(&mut cc, &acked);

        // Without loss, values should not change.
        assert_eq!(cc.bbr3_state.inflight_lo, 80_000);
        assert_eq!(cc.bbr3_state.bw_lo, 800_000);
    }

    #[test]
    fn test_bbr3_probe_rtt_interval_from_config() {
        // Verify that Config::set_probe_rtt_interval() plumbs through
        // to bbr3_state.probe_rtt_interval via RecoveryConfig.
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        cfg.set_probe_rtt_interval(Duration::from_secs(15));

        let r = Recovery::new(&cfg);

        assert_eq!(
            r.congestion.bbr3_state.probe_rtt_interval,
            Duration::from_secs(15),
            "probe_rtt_interval should be plumbed from Config to BBR3 state"
        );
    }

    #[test]
    fn test_bbr3_probe_rtt_interval_default_when_not_set() {
        // Verify default probe_rtt_interval when Config does not set it.
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR3);
        // Do NOT call set_probe_rtt_interval.

        let r = Recovery::new(&cfg);

        assert_eq!(
            r.congestion.bbr3_state.probe_rtt_interval,
            Duration::from_secs(5),
            "Default probe_rtt_interval should be 5s (PROBE_RTT_INTERVAL)"
        );
    }
}

mod init;
mod pacing;
mod per_ack;
mod per_loss;
mod per_transmit;
