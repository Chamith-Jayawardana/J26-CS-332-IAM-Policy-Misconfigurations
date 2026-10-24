"""
Consensus Voting Engine (Project J26-CS-332)
Implements 2-out-of-3 Majority Consensus across Checkov, Trivy, and KICS.
"""

from typing import List, Dict, Set, Tuple
from collections import Counter


class ConsensusVoter:
    """
    Applies 2-out-of-3 majority voting for resource-block findings.
    - >= 2 scanner votes: Labelled as Vulnerable (smell category assigned)
    - 0 scanner votes: Labelled as Safe
    - Exactly 1 scanner vote: Added to Contested Subset (reported separately)
    """

    def __init__(self, required_agreement: int = 2):
        self.required_agreement = required_agreement
        self.contested_blocks: List[Dict] = []

    def evaluate_block(
        self,
        block_id: str,
        scanner_findings: Dict[str, List[str]] # e.g. {"checkov": ["IAC_PUBLIC_STORAGE"], "trivy": ["IAC_PUBLIC_STORAGE"], "kics": []}
    ) -> Tuple[str, int, str]:
        """
        Returns:
            (status, agreement_count, determined_smell)
            status is one of: 'SAFE', 'CONSENSUS_VULNERABLE', 'CONTESTED'
        """
        all_smells = []
        reporting_scanners = set()

        for scanner, smells in scanner_findings.items():
            if smells:
                reporting_scanners.add(scanner)
                all_smells.extend(smells)

        if not reporting_scanners:
            return "SAFE", 0, "NONE"

        # Count occurrences of each smell across distinct scanners
        smell_votes = Counter()
        for smell in set(all_smells):
            count = sum(1 for scanner, s_list in scanner_findings.items() if smell in s_list)
            smell_votes[smell] = count

        # Check if any smell reached consensus (>= 2 votes)
        top_smell, top_count = smell_votes.most_common(1)[0]
        if top_count >= self.required_agreement:
            return "CONSENSUS_VULNERABLE", top_count, top_smell

        # If exactly 1 scanner reported findings or disagreement occurred
        self.contested_blocks.append({
            "block_id": block_id,
            "findings": scanner_findings
        })
        return "CONTESTED", top_count, top_smell

    def get_contested_count(self) -> int:
        return len(self.contested_blocks)
