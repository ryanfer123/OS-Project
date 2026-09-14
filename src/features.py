"""Fixed-length windows and simple behavioural features."""

from collections import Counter

import numpy as np


PAD_ID = 0
UNKNOWN_ID = 1
CATEGORIES = {
    "file": {"open", "openat", "read", "write", "close", "lseek", "stat", "fstat", "newfstatat", "mmap", "munmap"},
    "network": {"socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg"},
    "process": {"clone", "clone3", "fork", "vfork", "execve", "execveat", "wait4", "exit", "exit_group", "kill"},
    "permission": {"chmod", "fchmod", "chown", "fchown", "setuid", "setgid"},
}


def make_windows(calls: list[str], window_size: int) -> list[list[str]]:
    """Use half-overlapping windows and include the final full window."""
    if window_size < 2:
        raise ValueError("Window size must be at least 2")
    if len(calls) <= window_size:
        return [calls]
    stride = max(1, window_size // 2)
    starts = list(range(0, len(calls) - window_size + 1, stride))
    final_start = len(calls) - window_size
    if starts[-1] != final_start:
        starts.append(final_start)
    return [calls[start:start + window_size] for start in starts]


class FeatureEncoder:
    """Fit vocabulary on normal training traces; keep it fixed for inference."""

    def __init__(self, window_size: int = 10, max_pairs: int = 20, max_triples: int = 20):
        self.window_size = window_size
        self.max_pairs = max_pairs
        self.max_triples = max_triples
        self.vocabulary: dict[str, int] = {}
        self.common_pairs: list[tuple[int, int]] = []
        self.common_triples: list[tuple[int, int, int]] = []
        self.seen_pairs: set[tuple[int, int]] = set()

    def fit(self, traces: list[list[str]]) -> "FeatureEncoder":
        names = sorted({call for trace in traces for call in trace})
        self.vocabulary = {name: index + 2 for index, name in enumerate(names)}
        pair_counts: Counter = Counter()
        triple_counts: Counter = Counter()
        for trace in traces:
            for window in make_windows(trace, self.window_size):
                ids = self.encode(window)
                pair_counts.update(zip(ids, ids[1:]))
                triple_counts.update(zip(ids, ids[1:], ids[2:]))
        self.seen_pairs = set(pair_counts)
        self.common_pairs = [
            pair for pair, _ in sorted(pair_counts.items(), key=lambda item: (-item[1], item[0]))[:self.max_pairs]
        ]
        self.common_triples = [
            triple for triple, _ in sorted(triple_counts.items(), key=lambda item: (-item[1], item[0]))[:self.max_triples]
        ]
        return self

    def encode(self, calls: list[str]) -> list[int]:
        """Unknown names share one stable ID instead of changing feature shape."""
        return [self.vocabulary.get(call, UNKNOWN_ID) for call in calls]

    def encode_window(self, calls: list[str]) -> list[int]:
        """Represent even a short window with exactly window_size numeric IDs."""
        if not 1 <= len(calls) <= self.window_size:
            raise ValueError("Window must contain between 1 and window_size calls")
        return self.encode(calls) + [PAD_ID] * (self.window_size - len(calls))

    def transform_window(self, calls: list[str]) -> np.ndarray:
        encoded_window = self.encode_window(calls)
        ids = encoded_window[:len(calls)]  # Padding is excluded from behaviour counts.
        length = len(ids)
        counts = Counter(ids)
        pair_counts = Counter(zip(ids, ids[1:]))
        triple_counts = Counter(zip(ids, ids[1:], ids[2:]))
        pair_total = max(1, length - 1)
        triple_total = max(1, length - 2)
        known_pair_total = sum(pair_counts[pair] for pair in self.common_pairs)
        known_triple_total = sum(triple_counts[triple] for triple in self.common_triples)

        # Relative frequencies let short and full windows share the same scale.
        frequencies = [counts.get(call_id, 0) / length for call_id in range(1, len(self.vocabulary) + 2)]
        category_counts = [sum(call in names for call in calls) for names in CATEGORIES.values()]
        features = (
            frequencies
            + [len(set(calls)), length, counts.get(UNKNOWN_ID, 0)]
            + category_counts
            + [pair_counts[pair] / pair_total for pair in self.common_pairs]
            + [(pair_total - known_pair_total) / pair_total if length > 1 else 0.0]
            + [triple_counts[triple] / triple_total for triple in self.common_triples]
            + [(triple_total - known_triple_total) / triple_total if length > 2 else 0.0]
        )
        return np.asarray(features, dtype=float)

    def transform_trace(self, calls: list[str]) -> np.ndarray:
        return np.vstack([self.transform_window(window) for window in make_windows(calls, self.window_size)])

    def novelty_rates(self, calls: list[str]) -> tuple[float, float]:
        """Rates of unseen names and adjacent pairs in one window."""
        ids = self.encode(calls)
        unknown_rate = ids.count(UNKNOWN_ID) / len(ids)
        pairs = list(zip(ids, ids[1:]))
        unseen_pair_rate = sum(pair not in self.seen_pairs for pair in pairs) / len(pairs) if pairs else 0.0
        return unknown_rate, unseen_pair_rate
