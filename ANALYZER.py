"""
T&C Red Flag Scanner
Team: CorruptX
Analysis Engine

Modular rule-based NLP and risk taxonomy engine for Terms & Conditions, Privacy Policies, and EULAs.
Designed for 100% offline capability and drop-in extensibility for future LLM pipelines.
"""

import re
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

class ClauseAnalyzer:
    """
    Modular analysis engine that segments legal text into clauses,
    matches them against a cybersecurity risk taxonomy, and computes
    a deterministic 0-100 risk score with plain-English security explanations.
    """

    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            # Default to adjacent risk_rules.json
            current_dir = os.path.dirname(os.path.abspath(__file__))
            rules_path = os.path.join(current_dir, "risk_rules.json")
        self.rules_path = rules_path
        self.rules_data = self._load_rules()
        self.categories = self.rules_data.get("categories", [])
        self._compile_patterns()

    def _load_rules(self) -> Dict[str, Any]:
        """Load the cybersecurity taxonomy from JSON."""
        if not os.path.exists(self.rules_path):
            raise FileNotFoundError(f"Risk rules taxonomy file not found: {self.rules_path}")
        with open(self.rules_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _compile_patterns(self):
        """Pre-compile regex patterns for high-throughput clause evaluation."""
        self.compiled_rules = []
        for cat in self.categories:
            compiled_patterns = []
            for pattern_str in cat.get("patterns", []):
                try:
                    compiled_patterns.append(re.compile(pattern_str, re.IGNORECASE))
                except re.error as e:
                    print(f"Warning: Invalid regex in category {cat.get('id')}: {pattern_str} ({e})")
            self.compiled_rules.append({
                "id": cat.get("id"),
                "name": cat.get("name"),
                "severity": cat.get("severity", "LOW"),
                "weight": cat.get("weight", 5),
                "color": cat.get("color", "#38bdf8"),
                "explanation": cat.get("explanation", ""),
                "why_it_matters": cat.get("why_it_matters", ""),
                "recommendation": cat.get("recommendation", ""),
                "keywords": [k.lower() for k in cat.get("keywords", [])],
                "patterns": compiled_patterns
            })

    def clean_text(self, raw_text: str) -> str:
        """Sanitize and normalize text formatting without losing legal sentence boundaries."""
        if not raw_text:
            return ""

        # Replace smart quotes and dashes
        cleaned = raw_text.replace("“", "\"").replace("”", "\"")
        cleaned = cleaned.replace("‘", "'").replace("’", "'")
        cleaned = cleaned.replace("—", " - ").replace("–", " - ")

        # Normalize carriage returns and excessive tabs
        cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")

        # Remove null bytes or non-printable control characters
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)

        return cleaned.strip()

    def segment_clauses(self, text: str) -> List[str]:
        """
        Segment policy text into distinct clauses or sentences while preserving
        numbered sections (e.g. '1.1', 'Section 4(a)') and common abbreviations.
        """
        cleaned = self.clean_text(text)
        if not cleaned:
            return []

        # Mask known abbreviations that contain periods
        abbr_map = {
            r"\be\.g\.\b": "EG_TEMP_MARKER",
            r"\bi\.e\.\b": "IE_TEMP_MARKER",
            r"\bU\.S\.\b": "US_TEMP_MARKER",
            r"\betc\.\b": "ETC_TEMP_MARKER",
            r"\bInc\.\b": "INC_TEMP_MARKER",
            r"\bLtd\.\b": "LTD_TEMP_MARKER",
            r"\bLLC\.\b": "LLC_TEMP_MARKER",
            r"\bSec\.\b": "SEC_TEMP_MARKER",
            r"\bNo\.\b": "NO_TEMP_MARKER",
            r"\bv\.\b": "V_TEMP_MARKER",
            r"\bvs\.\b": "VS_TEMP_MARKER"
        }

        masked = cleaned
        for regex_pat, replacement in abbr_map.items():
            masked = re.sub(regex_pat, replacement, masked, flags=re.IGNORECASE)

        # Protect section numbering like 1.1 or 3.2.1
        masked = re.sub(r"(?<=\d)\.(?=\d)", "DECIMAL_DOT_MARKER", masked)

        # Split on double newlines or sentence-ending punctuation followed by space/newline
        # or numbered list items like \n1. or \n(a)
        chunks = re.split(r"(?:\n\s*\n|(?<=[.!?])\s+(?=[A-Z0-9\"'])|(?<=\n)\s*(?=[0-9]+\.\s|[A-Z]\.\s|\([a-z0-9]+\)\s))", masked)

        clauses = []
        for chunk in chunks:
            # Restore markers
            restored = chunk
            for regex_pat, replacement in abbr_map.items():
                marker_target = replacement
                original_sample = regex_pat.replace(r"\b", "").replace("\\", "")
                restored = restored.replace(marker_target, original_sample)

            restored = restored.replace("DECIMAL_DOT_MARKER", ".")
            restored = re.sub(r"\s+", " ", restored).strip()

            # Avoid single stray numbers or trivial fragments
            if len(restored) >= 12 or re.search(r"[a-zA-Z]{3,}", restored):
                clauses.append(restored)

        # If splitting resulted in no valid clauses but text was present, use full text
        if not clauses and len(cleaned) > 0:
            clauses = [cleaned]

        return clauses

    def is_negated_protection(self, clause_text: str, category_id: str) -> bool:
        """
        Detect if the clause explicitly promises protection via negation
        (e.g., 'we do not sell your data', 'we do not use device fingerprinting', 'never track').
        Protective clauses should not be flagged as red flags.
        """
        clause_lower = clause_text.lower()

        # Specific negative assertions by category that represent protections rather than risks
        negation_rules = {
            "data_sharing": [
                r"(?:we|company|our\s+service)\s+(?:do\s+not|will\s+not|does\s+not|never)\s+(?:sell|share|disclose|rent|monetize|transfer)",
                r"no\s+(?:third-party\s+sale|selling|sharing\s+with\s+third\s+parties)",
                r"(?:we\s+do\s+not|never)\s+disclose\s+personal\s+data"
            ],
            "tracking": [
                r"(?:we|company|our\s+service)\s+(?:do\s+not|will\s+not|does\s+not|never)\s+(?:track|use\s+tracking|record\s+keystrokes|fingerprint)",
                r"(?:no|zero)\s+(?:tracking|fingerprinting|telemetry|session\s+replay)",
                r"do\s+not\s+use\s+(?:tracking\s+cookies|device\s+fingerprinting|analytics\s+pixels)"
            ],
            "data_collection": [
                r"(?:we|company)\s+(?:do\s+not|will\s+not|does\s+not|never)\s+collect\s+(?:biometric|location|sensitive|contacts|files)",
                r"do\s+not\s+collect\s+location\s+data"
            ],
            "location_tracking": [
                r"(?:we|company)\s+(?:do\s+not|will\s+not|does\s+not|never)\s+(?:collect|track)\s+(?:your\s+)?location",
                r"do\s+not\s+collect\s+location\s+data"
            ],
            "advertising_profiling": [
                r"no\s+advertising\s+networks\s+are\s+embedded",
                r"(?:we|company)\s+(?:do\s+not|will\s+not|never)\s+(?:serve\s+targeted|profile|sell\s+ads)"
            ],
            "arbitration": [
                r"(?:we|company)\s+(?:do\s+not|will\s+not)\s+enforce\s+(?:mandatory\s+)?(?:binding\s+)?arbitration",
                r"do\s+not\s+enforce\s+mandatory\s+binding\s+arbitration"
            ]
        }

        cat_negations = negation_rules.get(category_id, [])
        for pat in cat_negations:
            if re.search(pat, clause_lower):
                return True
        return False

    def analyze_clause(self, clause_text: str, index: int) -> Dict[str, Any]:
        """
        Evaluate a single clause against the cybersecurity rule taxonomy.
        Returns matched risk details or clean status.
        """
        clause_lower = clause_text.lower()
        matched_categories = []

        for rule in self.compiled_rules:
            # First check if this clause is explicitly a privacy protection for this category
            if self.is_negated_protection(clause_text, rule["id"]):
                continue

            matched_flag = False
            matched_pattern_str = None

            # 1. Test regex patterns
            for pattern in rule["patterns"]:
                match = pattern.search(clause_text)
                if match:
                    matched_flag = True
                    matched_pattern_str = match.group(0)
                    break

            # 2. Test keywords if regex didn't trigger
            if not matched_flag:
                for kw in rule["keywords"]:
                    if kw in clause_lower:
                        matched_flag = True
                        matched_pattern_str = kw
                        break

            if matched_flag:
                matched_categories.append({
                    "category_id": rule["id"],
                    "category_name": rule["name"],
                    "severity": rule["severity"],
                    "weight": rule["weight"],
                    "color": rule["color"],
                    "explanation": rule["explanation"],
                    "why_it_matters": rule["why_it_matters"],
                    "recommendation": rule["recommendation"],
                    "snippet": matched_pattern_str
                })

        severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

        if matched_categories:
            # Sort by severity weight descending
            matched_categories.sort(
                key=lambda x: (severity_rank.get(x["severity"], 0), x["weight"]),
                reverse=True
            )
            top_match = matched_categories[0]

            return {
                "index": index,
                "text": clause_text,
                "is_flagged": True,
                "category_id": top_match["category_id"],
                "category_name": top_match["category_name"],
                "severity": top_match["severity"],
                "weight": top_match["weight"],
                "color": top_match["color"],
                "explanation": top_match["explanation"],
                "why_it_matters": top_match["why_it_matters"],
                "recommendation": top_match["recommendation"],
                "all_matched_categories": [m["category_name"] for m in matched_categories]
            }
        else:
            return {
                "index": index,
                "text": clause_text,
                "is_flagged": False,
                "category_id": None,
                "category_name": "Standard Clause",
                "severity": "SAFE",
                "weight": 0,
                "color": "#00ff88",
                "explanation": "No elevated risk indicators detected in this clause.",
                "why_it_matters": "Standard service provision or routine operational statement.",
                "recommendation": "Clause appears customary; verify context if unsure.",
                "all_matched_categories": []
            }

    def calculate_risk_score(self, total_clauses: int, flagged_clauses: List[Dict[str, Any]]) -> int:
        """
        Compute a reproducible 0-100 risk score based on:
        - Quantity and severity weights of detected red flags
        - Risk density relative to total document clauses
        - Guardrail thresholds (e.g. presence of multiple HIGH risks)
        """
        if total_clauses <= 0 or not flagged_clauses:
            return 5 # Baseline minimal score for empty/neutral policies

        high_count = sum(1 for c in flagged_clauses if c["severity"] == "HIGH")
        medium_count = sum(1 for c in flagged_clauses if c["severity"] == "MEDIUM")
        low_count = sum(1 for c in flagged_clauses if c["severity"] == "LOW")

        # Base weighted sum
        weighted_sum = (high_count * 16) + (medium_count * 8) + (low_count * 4)

        # Density factor: proportion of document containing red flags (up to 20 pts)
        density = len(flagged_clauses) / max(total_clauses, 1)
        density_bonus = min(20, int(density * 35))

        # Composite score
        raw_score = int((weighted_sum * 0.82) + density_bonus)

        # Guardrails for high-severity issues
        if high_count >= 3:
            raw_score = max(raw_score, 68)
        elif high_count >= 1:
            raw_score = max(raw_score, 42)
        elif medium_count >= 2:
            raw_score = max(raw_score, 35)

        # Final bounding to 0-100
        score = max(0, min(100, raw_score))
        return score

    def determine_risk_level(self, score: int) -> str:
        """Map 0-100 numerical score to formal risk tier."""
        if score <= 30:
            return "SAFE"
        elif score <= 60:
            return "CAUTION"
        else:
            return "HIGH RISK"

    def scan(self, text: str, document_name: str = "Submitted Policy") -> Dict[str, Any]:
        """
        Execute full end-to-end policy scan.
        Returns complete structured analysis ready for JSON transmission.
        """
        if not text or len(text.strip()) == 0:
            return {
                "error": "Input text is empty. Please paste or upload a policy to scan.",
                "risk_score": 0,
                "risk_level": "SAFE",
                "clauses_analyzed": 0,
                "red_flags": 0
            }

        clauses = self.segment_clauses(text)
        total_clauses = len(clauses)

        analyzed_clauses = []
        flagged_clauses = []

        category_counts: Dict[str, Dict[str, Any]] = {}

        for idx, clause in enumerate(clauses):
            res = self.analyze_clause(clause, idx)
            analyzed_clauses.append(res)
            if res["is_flagged"]:
                flagged_clauses.append(res)
                cat_id = res["category_id"]
                if cat_id not in category_counts:
                    category_counts[cat_id] = {
                        "category_id": cat_id,
                        "category_name": res["category_name"],
                        "severity": res["severity"],
                        "color": res["color"],
                        "count": 0,
                        "clauses": []
                    }
                category_counts[cat_id]["count"] += 1
                category_counts[cat_id]["clauses"].append(res["index"])

        score = self.calculate_risk_score(total_clauses, flagged_clauses)
        level = self.determine_risk_level(score)

        severity_counts = {
            "HIGH": sum(1 for c in flagged_clauses if c["severity"] == "HIGH"),
            "MEDIUM": sum(1 for c in flagged_clauses if c["severity"] == "MEDIUM"),
            "LOW": sum(1 for c in flagged_clauses if c["severity"] == "LOW")
        }

        # Format sorted categories for breakdown charts
        sorted_categories = sorted(
            list(category_counts.values()),
            key=lambda x: (x["count"], 3 if x["severity"] == "HIGH" else (2 if x["severity"] == "MEDIUM" else 1)),
            reverse=True
        )

        summary_msg = self._generate_summary(score, level, severity_counts, total_clauses)

        return {
            "document_name": document_name,
            "analyzed_at": datetime.now().isoformat(),
            "risk_score": score,
            "risk_level": level,
            "summary": summary_msg,
            "clauses_analyzed": total_clauses,
            "red_flags": len(flagged_clauses),
            "severity_counts": severity_counts,
            "categories": sorted_categories,
            "flagged_clauses": flagged_clauses,
            "all_clauses": analyzed_clauses,
            "disclaimer": "This tool provides automated cybersecurity risk analysis for informational purposes and is not a substitute for professional legal advice."
        }

    def _generate_summary(self, score: int, level: str, severities: Dict[str, int], total_clauses: int) -> str:
        """Construct a high-level executive security summary."""
        high = severities.get("HIGH", 0)
        med = severities.get("MEDIUM", 0)
        low = severities.get("LOW", 0)
        total_flags = high + med + low

        if level == "HIGH RISK":
            return (f"CRITICAL PRIVACY & LEGAL EXPOSURE DETECTED. Analysis identified {total_flags} red flags "
                    f"({high} High-Risk clauses) across {total_clauses} clauses. This policy contains terms that may "
                    f"severely compromise personal data privacy, waive legal remedies, or grant unilateral vendor control.")
        elif level == "CAUTION":
            return (f"MODERATE USER EXPOSURE DETECTED. Identified {total_flags} flagged clauses ({high} High, {med} Medium) "
                    f"out of {total_clauses} total clauses. Contains clauses such as recurring billing, data logging, "
                    f"or liability disclaimers that warrant conscious review before agreeing.")
        else:
            return (f"ACCEPTABLE RISK PROFILE. Minimal legal or data exposure detected across {total_clauses} clauses. "
                    f"Only {total_flags} minor items noted. Policy adheres to standard or user-friendly privacy practices.")
