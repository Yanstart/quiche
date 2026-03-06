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

use super::*;
use std::time::Duration;

// BBR2 Functions on every packet loss event.
//
// 4.2.4.  Per-Loss Steps
pub fn bbr2_update_on_loss(
    r: &mut Congestion, packet: &Sent, lost_bytes: usize, now: Instant,
) {
    bbr2_handle_lost_packet(r, packet, lost_bytes, now);
}

// 4.5.6.  Updating the Model Upon Packet Loss
// 4.5.6.2.  Probing for Bandwidth In ProbeBW
pub fn bbr2_check_inflight_too_high(r: &mut Congestion, now: Instant) -> bool {
    if bbr2_is_inflight_too_high(r) {
        if r.bbr2_state.bw_probe_samples {
            bbr2_handle_inflight_too_high(r, now);
        }

        // inflight too high.
        return true;
    }

    // inflight not too high.
    false
}

/// Get the effective loss threshold, applying RTT stability guard.
/// If RTT is inflated >30% above min_rtt, reverts to standard LOSS_THRESH
/// to avoid tolerating losses caused by real congestion.
fn effective_loss_threshold(r: &Congestion) -> f64 {
    let mut thresh = r.satellite_loss_threshold.unwrap_or(LOSS_THRESH);

    // RTT stability guard: if RTT inflated >30% above min, assume real
    // congestion
    if thresh > LOSS_THRESH {
        let min_rtt = r.bbr2_state.min_rtt;
        if min_rtt != Duration::MAX {
            let latest_rtt = r.delivery_rate.sample_rtt();
            if !latest_rtt.is_zero() && latest_rtt > min_rtt.mul_f64(1.3) {
                thresh = LOSS_THRESH; // Revert to standard threshold
            }
        }
    }

    thresh
}

pub fn bbr2_is_inflight_too_high(r: &mut Congestion) -> bool {
    let thresh = effective_loss_threshold(r);

    r.bbr2_state.lost > (r.bbr2_state.tx_in_flight as f64 * thresh) as usize
}

fn bbr2_handle_inflight_too_high(r: &mut Congestion, now: Instant) {
    // Only react once per bw probe.
    r.bbr2_state.bw_probe_samples = false;

    if !r.delivery_rate.sample_is_app_limited() {
        r.bbr2_state.inflight_hi = r
            .bbr2_state
            .tx_in_flight
            .max((per_ack::bbr2_target_inflight(r) as f64 * BETA) as usize);
    }

    if r.bbr2_state.state == BBR2StateMachine::ProbeBWUP {
        per_ack::bbr2_start_probe_bw_down(r, now);
    }
}

fn bbr2_handle_lost_packet(
    r: &mut Congestion, packet: &Sent, lost_bytes: usize, now: Instant,
) {
    if !r.bbr2_state.bw_probe_samples {
        return;
    }

    r.bbr2_state.tx_in_flight = packet.tx_in_flight;
    r.bbr2_state.lost = lost_bytes;

    r.delivery_rate.update_app_limited(packet.is_app_limited);

    // Satellite bit-error vs congestion loss discrimination.
    // Isolated losses (inter-loss gap > 2 * min_rtt) are likely BER,
    // not congestion. Skip the congestion response for these.
    if r.satellite_loss_discrimination {
        let is_isolated = match r.bbr2_state.last_loss_time {
            Some(last) => {
                let gap = now.duration_since(last);
                let min_rtt = r.bbr2_state.min_rtt;
                min_rtt != Duration::MAX && gap > min_rtt.mul_f64(2.0)
            }
            None => true, // First loss -- assume isolated
        };
        r.bbr2_state.last_loss_time = Some(now);

        if is_isolated {
            r.bbr2_state.consecutive_isolated_losses += 1;
            return; // Skip congestion response for isolated bit error
        } else {
            r.bbr2_state.consecutive_isolated_losses = 0;
            // Track this as a congestion loss (passed discrimination).
            r.bbr2_state.congestion_losses_in_round += 1;
        }
    } else {
        // Discrimination disabled: all losses count as congestion losses.
        r.bbr2_state.congestion_losses_in_round += 1;
    }

    if bbr2_is_inflight_too_high(r) {
        r.bbr2_state.tx_in_flight = bbr2_inflight_hi_from_lost_packet(r, packet);

        bbr2_handle_inflight_too_high(r, now);
    }
}

fn bbr2_inflight_hi_from_lost_packet(r: &mut Congestion, packet: &Sent) -> usize {
    let size = packet.size;
    let inflight_prev = r.bbr2_state.tx_in_flight - size;
    let lost_prev = r.bbr2_state.lost - size;
    let thresh = effective_loss_threshold(r);
    let lost_prefix = (thresh * inflight_prev as f64 - lost_prev as f64) /
        (1.0 - thresh);

    inflight_prev + lost_prefix as usize
}

// 4.5.6.3.  When not Probing for Bandwidth
pub fn bbr2_update_latest_delivery_signals(r: &mut Congestion) {
    let bbr = &mut r.bbr2_state;

    // Near start of ACK processing.
    bbr.loss_round_start = false;
    bbr.bw_latest = bbr.bw_latest.max(r.delivery_rate.sample_delivery_rate());
    bbr.inflight_latest =
        bbr.inflight_latest.max(r.delivery_rate.sample_delivered());

    if r.delivery_rate.sample_prior_delivered() >= bbr.loss_round_delivered {
        bbr.loss_round_delivered = r.delivery_rate.delivered();
        bbr.loss_round_start = true;
    }
}

pub fn bbr2_advance_latest_delivery_signals(r: &mut Congestion) {
    let bbr = &mut r.bbr2_state;

    // Near end of ACK processing.
    if bbr.loss_round_start {
        bbr.bw_latest = r.delivery_rate.sample_delivery_rate();
        bbr.inflight_latest = r.delivery_rate.sample_delivered();
    }
}

pub fn bbr2_reset_congestion_signals(r: &mut Congestion) {
    let bbr = &mut r.bbr2_state;

    bbr.loss_in_round = false;
    bbr.loss_events_in_round = 0;
    bbr.congestion_losses_in_round = 0;
    bbr.bw_latest = 0;
    bbr.inflight_latest = 0;
}

pub fn bbr2_update_congestion_signals(r: &mut Congestion, packet: &Acked) {
    // Update congestion state on every ACK.
    per_ack::bbr2_update_max_bw(r, packet);

    if r.bbr2_state.lost > 0 {
        // When satellite loss discrimination is enabled, only set
        // loss_in_round if at least one loss in this round was classified
        // as congestion (not an isolated bit error). This prevents
        // bbr2_loss_lower_bounds() from reducing bw_lo/inflight_lo
        // for BER-only rounds.
        if r.satellite_loss_discrimination {
            if r.bbr2_state.congestion_losses_in_round > 0 {
                r.bbr2_state.loss_in_round = true;
            }
        } else {
            r.bbr2_state.loss_in_round = true;
        }
        r.bbr2_state.loss_events_in_round += 1;
    }

    if !r.bbr2_state.loss_round_start {
        // Wait until end of round trip.
        return;
    }

    bbr2_adapt_lower_bounds_from_congestion(r);

    r.bbr2_state.loss_in_round = false;
    r.bbr2_state.loss_events_in_round = 0;
    r.bbr2_state.congestion_losses_in_round = 0;
}

fn bbr2_adapt_lower_bounds_from_congestion(r: &mut Congestion) {
    // Once per round-trip respond to congestion.
    if bbr2_is_probing_bw(r) {
        return;
    }

    if r.bbr2_state.loss_in_round {
        bbr2_init_lower_bounds(r);
        bbr2_loss_lower_bounds(r);
    }
}

fn bbr2_init_lower_bounds(r: &mut Congestion) {
    let bbr = &mut r.bbr2_state;

    // Handle the first congestion episode in this cycle.
    if bbr.bw_lo == u64::MAX {
        bbr.bw_lo = bbr.max_bw;
    }

    if bbr.inflight_lo == usize::MAX {
        bbr.inflight_lo = r.congestion_window;
    }
}

fn bbr2_loss_lower_bounds(r: &mut Congestion) {
    let bbr = &mut r.bbr2_state;

    // Adjust model once per round based on loss.
    bbr.bw_lo = bbr.bw_latest.max((bbr.bw_lo as f64 * BETA) as u64);
    bbr.inflight_lo = bbr
        .inflight_latest
        .max((bbr.inflight_lo as f64 * BETA) as usize);
}

pub fn bbr2_reset_lower_bounds(r: &mut Congestion) {
    let bbr = &mut r.bbr2_state;

    bbr.bw_lo = u64::MAX;
    bbr.inflight_lo = usize::MAX;
}

pub fn bbr2_bound_bw_for_model(r: &mut Congestion) {
    let bbr = &mut r.bbr2_state;

    bbr.bw = bbr.max_bw.min(bbr.bw_lo.min(bbr.bw_hi));
}

// This function is not defined in the draft but used.
fn bbr2_is_probing_bw(r: &mut Congestion) -> bool {
    let state = r.bbr2_state.state;

    state == BBR2StateMachine::Startup ||
        state == BBR2StateMachine::ProbeBWREFILL ||
        state == BBR2StateMachine::ProbeBWUP
}
