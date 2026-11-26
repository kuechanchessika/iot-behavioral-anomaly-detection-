"""ADWIN (Adaptive Windowing) Drift Engine & Statistical Variance Tracking.

Layer 2: AI-Powered Behavioral Anomaly Detection Pipeline
Stage 1: Feature Extraction & Adaptive State Tracking (Function 2)

Based on:
- Bifet & Gavaldà (2007): 'Learning from time-changing data with adaptive windowing'
- Week 8 Research Progress Report: Replacing Static 5-Minute Window with ADWIN
- Week 9 Research Progress Report: Mathematical Redesign with SLA Confidence (delta)
  and Empirical Dynamic Dispersion Bounding via Bernstein's Inequality.
"""

import math
from typing import Dict, List, Optional, Tuple, Union
import numpy as np

from src.config import (
    ADWIN_DELTA_BENCHMARK,
    ADWIN_DELTA_SLA,
    ADWIN_DEFAULT_R,
    ALPHA_TARGET,
    N_HORIZON,
)


class WelfordRunningStats:
    """O(1) Running mean and sample variance calculator using Welford's algorithm.
    
    Guarantees numerical stability and constant-time updates for high-throughput
    IoT edge routers without needing to store or re-traverse raw packet histories.
    """

    def __init__(self):
        self.count: int = 0
        self.mean: float = 0.0
        self._m2: float = 0.0

    def update(self, x: float) -> None:
        """Add a single observation and update running moments in O(1)."""
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self._m2 += delta * delta2

    def remove(self, x: float) -> None:
        """Remove an observation (for sliding windows) in O(1)."""
        if self.count <= 1:
            self.reset()
            return
        self.count -= 1
        delta = x - self.mean
        self.mean -= delta / self.count
        delta2 = x - self.mean
        self._m2 -= delta * delta2
        if self._m2 < 0.0:
            self._m2 = 0.0

    def reset(self) -> None:
        self.count = 0
        self.mean = 0.0
        self._m2 = 0.0

    @property
    def variance(self) -> float:
        """Unbiased sample variance sigma_hat^2 (ddof=1)."""
        if self.count < 2:
            return 0.0
        return self._m2 / (self.count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


class ADWINPortDriftEngine:
    """Adaptive Windowing (ADWIN) engine for IoT port-scan and behavioral drift detection.
    
    Replaces brittle 5-minute fixed sliding windows with event-driven statistical
    hypothesis testing. Automatically maintains normal baseline history as long as
    traffic behavior stays stationary, and drops obsolete history when a genuine shift occurs.
    """

    def __init__(
        self,
        delta: Optional[float] = None,
        use_bernstein: bool = False,
        default_range: float = ADWIN_DEFAULT_R,
        min_subwindow_len: int = 2,
    ):
        # Default to SLA-budgeted confidence: delta = alpha_target / N_horizon (Week 9)
        self.delta: float = delta if delta is not None else ADWIN_DELTA_BENCHMARK
        self.use_bernstein: bool = use_bernstein
        self.default_range: float = default_range
        self.min_subwindow_len: int = min_subwindow_len

        self.window: List[float] = []
        self.welford: WelfordRunningStats = WelfordRunningStats()
        self.last_drift_value: float = 0.0
        self.drift_detected_flag: bool = False
        self.total_observations: int = 0
        self.total_drifts_detected: int = 0

    def reset(self) -> None:
        """Clear observation history and reset state statistics."""
        self.window.clear()
        self.welford.reset()
        self.last_drift_value = 0.0
        self.drift_detected_flag = False

    @staticmethod
    def compute_harmonic_sample_size(n0: int, n1: int) -> float:
        """Harmonic sample size m = 1 / (1/n0 + 1/n1).
        
        Accounts for differences in observation sizes between old and recent subwindows.
        """
        if n0 <= 0 or n1 <= 0:
            return 0.0
        return 1.0 / (1.0 / n0 + 1.0 / n1)

    @staticmethod
    def compute_hoeffding_threshold(
        m: float,
        n: int,
        delta: float,
        r_dyn: float = 1.0
    ) -> Tuple[float, float]:
        """Compute adjusted confidence delta' and Hoeffding cut hurdle epsilon_cut.
        
        Formulas:
            delta' = delta / n
            epsilon_cut = sqrt( (r_dyn^2 / (2 * m)) * ln(4 / delta') )
        """
        if m <= 0 or n <= 0 or delta <= 0:
            return 0.0, 0.0
        delta_prime = delta / n
        ratio = 4.0 / delta_prime
        ln_term = math.log(ratio) if ratio > 0 else 0.0
        variance_factor = (r_dyn ** 2) / (2.0 * m)
        epsilon_cut = math.sqrt(variance_factor * ln_term)
        return delta_prime, epsilon_cut

    @staticmethod
    def compute_bernstein_threshold(
        m: float,
        n: int,
        delta: float,
        sample_variance: float,
        r_dyn: float
    ) -> float:
        """Empirical Bernstein cut hurdle scaling by sample variance (Week 9).
        
        Formula:
            epsilon_cut_Bernstein = sqrt( (2 * sigma_hat^2 / m) * ln(4n / delta) )
                                    + (R_dyn / (3 * m)) * ln(4n / delta)
        """
        if m <= 0 or n <= 0 or delta <= 0:
            return 0.0
        ln_term = math.log(4.0 * n / delta)
        term1 = math.sqrt((2.0 * max(0.0, sample_variance) / m) * ln_term)
        term2 = (r_dyn / (3.0 * m)) * ln_term
        return term1 + term2

    def add_observation(self, x: float) -> Tuple[bool, float]:
        """Ingest a new numerical observation (e.g., unique destination port count).
        
        Returns:
            Tuple[drift_detected (bool), adwin_port_drift (float)]
        """
        self.window.append(float(x))
        self.welford.update(float(x))
        self.total_observations += 1
        self.drift_detected_flag = False

        n = len(self.window)
        if n < self.min_subwindow_len * 2:
            return False, 0.0

        r_dyn = max(self.window) - min(self.window)
        if r_dyn <= 0:
            r_dyn = 1.0  # Avoid zero division or null bounds when all readings are identical

        sample_var = self.welford.variance

        # Check all possible split partitions of the window W into W0 and W1
        # Start from min_subwindow_len up to n - min_subwindow_len
        drift_found = False
        split_idx = -1
        max_d = 0.0

        for i in range(self.min_subwindow_len, n - self.min_subwindow_len + 1):
            w0 = self.window[:i]
            w1 = self.window[i:]
            n0 = len(w0)
            n1 = len(w1)

            mu0 = sum(w0) / n0
            mu1 = sum(w1) / n1
            d = abs(mu0 - mu1)

            m = self.compute_harmonic_sample_size(n0, n1)

            if self.use_bernstein:
                eps_cut = self.compute_bernstein_threshold(m, n, self.delta, sample_var, r_dyn)
            else:
                _, eps_cut = self.compute_hoeffding_threshold(m, n, self.delta, r_dyn=1.0)

            if d > eps_cut:
                drift_found = True
                split_idx = i
                max_d = d
                break  # Detect earliest statistically significant change

        if drift_found and split_idx > 0:
            self.drift_detected_flag = True
            self.last_drift_value = round(max_d, 4)
            self.total_drifts_detected += 1

            # Cut old baseline history W0 from window, retain W1
            removed_items = self.window[:split_idx]
            self.window = self.window[split_idx:]

            # Rebuild Welford statistics for remaining subwindow
            self.welford.reset()
            for val in self.window:
                self.welford.update(val)

            return True, self.last_drift_value

        return False, 0.0

    @classmethod
    def step_by_step_calculation(
        cls,
        w: List[float],
        n0: int,
        delta: float = ADWIN_DELTA_BENCHMARK,
    ) -> Dict[str, Union[float, int, bool, str, List[float]]]:
        """Perform the exact 6-step ADWIN mathematical calculation from Week 8 & 9 reports.
        
        Given sequence W and split boundary n0:
            W0 = W[:n0], W1 = W[n0:]
        
        Returns all intermediate mathematical steps for verification and auditing.
        """
        w0 = [float(x) for x in w[:n0]]
        w1 = [float(x) for x in w[n0:]]
        n1 = len(w1)
        n = n0 + n1

        # Step 1: Calculate Average old data
        mu0 = sum(w0) / n0

        # Step 2: Calculate Average new data
        mu1 = sum(w1) / n1

        # Step 3: Calculate difference between 2 averages (D)
        d = abs(mu0 - mu1)

        # Step 4: Calculate harmonic sample
        m = cls.compute_harmonic_sample_size(n0, n1)

        # Step 5: Calculate Threshold Hurdle (epsilon_cut)
        # 5.1 Adjusted confidence (delta')
        delta_prime = delta / n

        # 5.2 Threshold Formula (Hoeffding)
        ln_ratio = math.log(4.0 / delta_prime)
        variance_factor = 1.0 / (2.0 * m)
        eps_cut_hoeffding = math.sqrt(variance_factor * ln_ratio)

        # Bernstein formulation (Week 9)
        r_dyn = max(w) - min(w)
        sample_var = float(np.var(w, ddof=1)) if len(w) > 1 else 0.0
        eps_cut_bernstein = cls.compute_bernstein_threshold(m, n, delta, sample_var, r_dyn)

        # Step 6: Make Decision
        drift_detected = bool(d > eps_cut_hoeffding)

        return {
            "W": w,
            "W0": w0,
            "W1": w1,
            "n0": n0,
            "n1": n1,
            "n": n,
            "delta": delta,
            "mu0": round(mu0, 4),
            "mu1": round(mu1, 4),
            "D": round(d, 4),
            "m": round(m, 4),
            "delta_prime": delta_prime,
            "ln_4_over_delta_prime": round(ln_ratio, 4),
            "epsilon_cut_hoeffding": round(eps_cut_hoeffding, 4),
            "R_dyn": r_dyn,
            "sample_variance": round(sample_var, 4),
            "epsilon_cut_bernstein": round(eps_cut_bernstein, 4),
            "drift_detected": drift_detected,
            "adwin_port_drift": round(d, 4) if drift_detected else 0.0,
        }
