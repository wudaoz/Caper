"""Regex corrections that were withdrawn: the released matches are kept for these tasks."""
from .boundary import BoundaryOracle, demotion_reason


class Oracle(BoundaryOracle):
    """Restore the released matches demoted by the three evidence filters (regex_evidence.py)."""
    def regex(self, trajectory, ground_truth, task_id=None):
        matches, candidates = super().regex(trajectory, ground_truth, task_id=task_id)
        accepted = list(matches)
        kept = []
        for candidate in candidates:
            if candidate.get('evidence_source') == 'frozen_trajectory_post_match_filter':
                restored = {k: v for k, v in candidate.items() if k not in {'matched', 'candidate_reason'}}
                restored['evidence_source'] = 'executed_command'
                reason = demotion_reason(restored['command'], restored['pattern'])
                if reason:
                    kept.append({**candidate, 'candidate_reason': reason})
                else:
                    accepted.append(restored)
            else:
                kept.append(candidate)
        return accepted, kept
