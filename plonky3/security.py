#!/usr/bin/env python3
"""
Python port from modified calculation in lean_multisig.

A pure Reed-Solomon / Johnson-bound query-soundness calculation. Uses ONLY the generic
coding-theory pieces of `SecurityAssumption` (ported from crates/whir/src/config.rs):
log_eta, list_size_bits, prox_gaps_error, log_1_delta, queries, queries_error.

It touches nothing WHIR-specific (no sumcheck folding-soundness, no OOD, no rate-shift loop):
"for a codeword committed at rate rho = 2^-log_inv_rate, how many Merkle-opening queries
does a single-oracle proximity test need for `security_level` bits, and what is the proven
soundness, accounting for both the query phase and the commit/proximity-gaps phase?"

Run:  python3 security.py
"""

import math


# ---------------------------------------------------------------------------
# SecurityAssumption::JohnsonBound  (port of crates/whir/src/config.rs)
# ---------------------------------------------------------------------------

def log_eta(log_inv_rate: int, log_c: float) -> float:
    """log2 of the proximity slack eta. Johnson bound: eta = sqrt(rho)/c."""
    # eta = sqrt(rho)/c  ->  log2(eta) = -(0.5*log_inv_rate + log_c)
    return -(0.5 * log_inv_rate + log_c)


def list_size_bits(log_inv_rate: int, log_c: float) -> float:
    """Johnson: RS codes are (1 - sqrt(rho) - eta, (2*eta*sqrt(rho))^-1)-list decodable."""
    le = log_eta(log_inv_rate, log_c)
    log_inv_sqrt_rate = log_inv_rate / 2.0
    return log_inv_sqrt_rate - (1.0 + le)


def prox_gaps_error(log_degree: int, log_inv_rate: int, field_size_bits: int,
                    num_functions: int, log_c: float) -> float:
    """Proximity-gaps error in bits at the Johnson distance (BCSS25 Theorem 1.5)."""
    le = log_eta(log_inv_rate, log_c)
    eta = 2.0 ** le
    rho = 1.0 / (1 << log_inv_rate)
    rho_sqrt = math.sqrt(rho)
    gamma = 1.0 - rho_sqrt - eta
    n = float(1 << (log_degree + log_inv_rate))
    m = max(math.ceil(rho_sqrt / (2.0 * eta)), 3)
    num_1 = (2.0 * (m + 0.5) ** 5 + 3.0 * (m + 0.5) * gamma * rho) * n
    den_1 = 3.0 * rho * rho_sqrt
    num_2 = m + 0.5
    den_2 = rho_sqrt
    error = math.log2((num_1 / den_1) + (num_2 / den_2))
    # error is (num_functions - 1) * error / |F|; log2(num_functions - 1) = 0 when num_functions = 2.
    num_functions_1_log = math.log2(num_functions - 1)
    return field_size_bits - (error + num_functions_1_log)


def log_1_delta(log_inv_rate: int, log_c: float) -> float:
    """log2(1 - delta) where delta = 1 - sqrt(rho) - eta is the Johnson decoding radius."""
    eta = 2.0 ** log_eta(log_inv_rate, log_c)
    rate = 1.0 / (1 << log_inv_rate)
    delta = 1.0 - math.sqrt(rate) - eta
    return math.log2(1.0 - delta)


def queries(protocol_security_level: int, log_inv_rate: int, log_c: float) -> int:
    """Number of queries to match the security level: ceil(-sec / log2(1 - delta))."""
    return math.ceil(-protocol_security_level / log_1_delta(log_inv_rate, log_c))


def queries_error(log_inv_rate: int, num_queries: int, log_c: float) -> float:
    """Query soundness for `num_queries` queries: -num_queries * log2(1 - delta)."""
    return -num_queries * log_1_delta(log_inv_rate, log_c)


# ---------------------------------------------------------------------------
# run_generic
# ---------------------------------------------------------------------------

def run_generic(label: str, security_level: int, query_pow_bits: int, commit_pow_bits: int,
                log_inv_rate: int,  field_size_bits: int, log_degree: int, num_columns: int) -> None:
    qsl = security_level - query_pow_bits

    assert field_size_bits > security_level, "field must exceed security level"
    print(f"\n===== {label}: field_size_bits = {field_size_bits} =====")
    print(f"rho = 2^-{log_inv_rate}, security = {security_level}, "
          f"query_pow = {query_pow_bits}, commit_pow = {commit_pow_bits} "
          f"-> query_security_level = {qsl}")

    # queries() is non-increasing in log_c and feasibility is a prefix in m
    # (prox_gaps_error is monotone-decreasing in log_c), so the LARGEST feasible m attains
    # the minimum query count. commit-phase grinding adds straight onto the proximity-gaps
    # headroom (a separate budget from the query grind already removed via qsl).
    chosen_m = None
    for m in range(3, 101):
        log_c = math.log2(2.0 * m)
        # num_functions = 2: generic RS proximity gap of a 2-element line {f0, f0 + r*f1}.
        prox = prox_gaps_error(log_degree, log_inv_rate, field_size_bits, 2, log_c)
        if prox + commit_pow_bits < security_level:
            break
        chosen_m = m

    # prox_gaps_error is maximized at the smallest log_c (m=3). If NO m is feasible, the
    # commit phase (even with commit grinding) caps below the target: UNREACHABLE at this
    # field/degree/rate -- no number of queries can fix it.
    if chosen_m is None:
        max_prox = prox_gaps_error(log_degree, log_inv_rate, field_size_bits, 2, math.log2(2.0 * 3.0))
        print(f"  UNREACHABLE: prox_gaps caps at {max_prox:.1f} + {commit_pow_bits} commit_pow = "
              f"{max_prox + commit_pow_bits:.1f} bits < security {security_level} "
              f"(need bigger field / smaller log_degree / smaller rate / more commit_pow)")
        return

    chosen_log_c = math.log2(2.0 * chosen_m)

    eta = 2.0 ** log_eta(log_inv_rate, chosen_log_c)
    rho = 1.0 / (2 ** log_inv_rate)
    delta = 1.0 - math.sqrt(rho) - eta  # Johnson decoding radius actually used
    l1d = log_1_delta(log_inv_rate, chosen_log_c)
    num_queries = queries(qsl, log_inv_rate, chosen_log_c)
    achieved = queries_error(log_inv_rate, num_queries, chosen_log_c)

    print(f"  chosen (largest feasible m, prox_gaps_error >= {security_level}): "
          f"m={chosen_m}, log_c={chosen_log_c:.3f}")
    print(f"  sqrt(rho)={math.sqrt(rho):.5f}  eta={eta:.6f}  "
          f"delta = 1 - sqrt(rho) - eta = {delta:.5f}")
    print(f"  log2(1 - delta) = {l1d:.4f}")
    print(f"  num_queries = ceil({qsl} / {-l1d:.4f}) = {num_queries}")

    # Proven soundness is min(query_phase, commit_phase) -- NOT the query phase alone.
    # Because we pick the largest feasible m, the commit phase is driven down to ~security_level
    # (the break boundary) and is the binding side, even though the query phase often sits higher.
    commit_total = prox_gaps_error(log_degree, log_inv_rate, field_size_bits, num_columns, chosen_log_c) + commit_pow_bits
    query_total = achieved + query_pow_bits
    print(f"  query phase  = {query_total:.1f} bits (achieved {achieved:.2f} + {query_pow_bits} query_pow)")
    print(f"  commit phase = {commit_total:.1f} bits (prox + {commit_pow_bits} commit_pow)")
    print(f"  => proven soundness = min = {min(query_total, commit_total):.1f} bits")


def main() -> None:
    security_level = 100
    query_pow_bits = 16   # grind backing the QUERY phase; the rest must come from queries
    commit_pow_bits = 16  # grind backing the COMMIT/proximity-gaps phase (separate budget)
    log_inv_rate = 16      # log_blowup -> rho = 2^-4
    air_log_degree = 13       # log2 of the message length (only used by the list/prox-gap terms)
    air_num_columns = 2

    # field_size_bits is the EXTENSION field size = bits per Fiat-Shamir challenge.
    #   KoalaBear^4 = 4*31 = 124
    #   KoalaBear^5 = 5*31 = 155   (what leanVM uses)
    #   Goldilocks^2 = 2*64 = 128
    #   Goldilocks^3 = 3*64 = 192
    for label, field_size_bits in [
        ("KoalaBear^4", 124),
        ("KoalaBear^5 (leanVM)", 155),
        ("Goldilocks^2", 128),
        ("Goldilocks^3", 192),
    ]:
        run_generic(label, security_level, query_pow_bits, commit_pow_bits,
                    log_inv_rate, field_size_bits, air_log_degree, air_num_columns)


if __name__ == "__main__":
    main()
