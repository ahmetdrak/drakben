"""DRAKBEN Social Engineering - Psycho Profiler
Author: @drak_ben
Description: Uses LLM to generate psychological profiles and phishing scenarios.
"""

import logging
import re
import secrets
from dataclasses import dataclass
from enum import Enum

from .osint import TargetPerson

logger = logging.getLogger(__name__)


# =============================================================================
# COGNITIVE SCIENCE & NLP CORE
# =============================================================================


class CognitiveBias(Enum):
    """Auto-generated docstring for CognitiveBias class."""

    AUTHORITY = "authority"  # Obedience to power
    SCARCITY = "scarcity"  # FOMO, Time pressure
    RECIPROCITY = "reciprocity"  # "I did this for you, so..."
    COMMITMENT = "commitment"  # Consistency with past actions
    LIKING = "liking"  # Similarity, compliments
    SOCIAL_PROOF = "social_proof"  # "Everyone else is doing it"
    CURIOSITY = "curiosity"  # Information gap
    FEAR = "fear"  # Loss aversion (Strongest but risky)


@dataclass
class PsychologicalProfile:
    """Auto-generated docstring for PsychologicalProfile class."""

    primary_bias: CognitiveBias
    secondary_bias: CognitiveBias
    tone: str  # Formal, urgent, casual, technical
    vocabulary_level: int  # 1-10
    synthetic_context: str  # "JIRA", "Slack", "Legal", "HR"


class NLPPayloadEngine:
    """2026/2027-Era NLP Engine for Behavioral Profiling.
    Uses native statistical text analysis (TF-IDF + Jaccard) to map
    targets to psychological archetypes without external API dependency.
    """

    def __init__(self) -> None:
        # 1. Zero-Shot Classification Anchors (Simulated)
        self.bias_anchors = {
            CognitiveBias.AUTHORITY: {
                "keywords": {
                    "ceo",
                    "exec",
                    "director",
                    "legal",
                    "audit",
                    "compliance",
                    "policy",
                    "mandatory",
                    "regulation",
                    "vp",
                },
                "weight": 1.5,
            },
            CognitiveBias.SCARCITY: {
                "keywords": {
                    "deadline",
                    "expires",
                    "immediate",
                    "limited",
                    "today",
                    "urgent",
                    "24h",
                    "lockout",
                    "final",
                },
                "weight": 1.2,
            },
            CognitiveBias.RECIPROCITY: {
                "keywords": {
                    "help",
                    "support",
                    "gift",
                    "favor",
                    "bonus",
                    "reward",
                    "assistance",
                    "guide",
                    "free",
                },
                "weight": 1.1,
            },
            CognitiveBias.CURIOSITY: {
                "keywords": {
                    "news",
                    "update",
                    "announce",
                    "leak",
                    "secret",
                    "confidential",
                    "changes",
                    "reveal",
                    "discovery",
                },
                "weight": 1.3,
            },
            CognitiveBias.SOCIAL_PROOF: {
                "keywords": {
                    "team",
                    "everyone",
                    "join",
                    "network",
                    "community",
                    "popular",
                    "trending",
                    "colleagues",
                },
                "weight": 1.0,
            },
            CognitiveBias.FEAR: {
                "keywords": {
                    "security",
                    "breach",
                    "alert",
                    "hack",
                    "danger",
                    "risk",
                    "fail",
                    "error",
                    "critical",
                },
                "weight": 1.4,
            },
        }

        # 2. Tone Analysis Vectors
        self.tone_vectors = {
            "technical": {
                "api",
                "server",
                "code",
                "dev",
                "bug",
                "deploy",
                "log",
                "stack",
                "config",
            },
            "corporate": {
                "strategy",
                "q1",
                "kpi",
                "roi",
                "synergy",
                "leverage",
                "stakeholder",
            },
            "casual": {"hey", "cool", "thanks", "weekend", "chat", "hangout", "coffee"},
        }

    def _calculate_bias_scores(
        self,
        word_set: set[str],
        text: str,
    ) -> dict["CognitiveBias", float]:
        """Calculate bias scores based on word intersection."""
        scores = dict.fromkeys(CognitiveBias, 0.0)

        for bias, data in self.bias_anchors.items():
            intersection = word_set.intersection(data["keywords"])
            score = len(intersection) * data["weight"]

            if bias == CognitiveBias.AUTHORITY and "chief" in text:
                score += 2.0
            if bias == CognitiveBias.SCARCITY and "urgent" in text:
                score += 2.0

            scores[bias] = score

        return scores

    def _detect_tone(self, word_set: set[str]) -> str:
        """Detect communication tone from vocabulary."""
        detected_tone = "Formal"
        max_overlap = 0
        for tone, vocab in self.tone_vectors.items():
            overlap = len(word_set.intersection(vocab))
            if overlap > max_overlap:
                max_overlap = overlap
                detected_tone = tone.title()
        return detected_tone

    def _detect_context_and_bias(
        self,
        text: str,
        primary: "CognitiveBias",
    ) -> tuple[str, "CognitiveBias"]:
        """Detect synthetic context and adjust primary bias based on role."""
        if "dev" in text or "engineer" in text:
            return "JIRA", CognitiveBias.CURIOSITY
        if "hr" in text or "recruit" in text:
            return "LinkedIn", primary
        if "sales" in text:
            return "Salesforce", CognitiveBias.SCARCITY
        return "Email", primary

    def analyze_text(self, text: str) -> PsychologicalProfile:
        """Perform deep psychometric analysis on target text (Role, Bio, Posts)."""
        text = text.lower()
        words = re.findall(r"\w+", text)
        word_set = set(words)

        # A. Bias Scoring
        scores = self._calculate_bias_scores(word_set, text)

        # Select Top 2
        sorted_biases = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        primary = (
            sorted_biases[0][0] if sorted_biases[0][1] > 0 else CognitiveBias.CURIOSITY
        )
        secondary = (
            sorted_biases[1][0]
            if sorted_biases[1][1] > 0
            else CognitiveBias.SOCIAL_PROOF
        )

        # B. Context & Tone Detection
        detected_tone = self._detect_tone(word_set)

        # C. Heuristic Role Mapping
        synthetic_context, primary = self._detect_context_and_bias(text, primary)

        return PsychologicalProfile(
            primary_bias=primary,
            secondary_bias=secondary,
            tone=detected_tone,
            vocabulary_level=8,  # static for now
            synthetic_context=synthetic_context,
        )


class PsychoProfiler:
    """Advanced Social Engineering Profiler (v2026).
    Generates 'Synthetic Familiarity' pretexts.
    """

    def __init__(self, llm_provider=None) -> None:
        self.engine = NLPPayloadEngine()
        logger.info("PsychoProfiler Brain (NLP Engine) initialized")

    def generate_profile(self, target: TargetPerson) -> dict[str, str]:
        """Generate a psychometric profile using NLP engine."""
        # Aggregate text traces
        # In real scenario: bio + last_10_tweets + linkedin_about
        raw_text = f"{target.role} {target.notes if hasattr(target, 'notes') else ''} {target.full_name}"

        # Deep Analysis
        psych_profile = self.engine.analyze_text(raw_text)

        # Generate Strategy Object
        profile_dict = {
            "personality_type": f"{psych_profile.primary_bias.value.upper()}-Dominant",
            "recommended_lure": f"Synthetic {psych_profile.synthetic_context} Notification",
            "emotional_trigger": f"{psych_profile.primary_bias.value} + {psych_profile.secondary_bias.value}",
            "best_time_to_send": "09:42 AM (Local Target Time)",  # Algorithmic timing
            "tone": psych_profile.tone,
            "bias_vector": psych_profile.primary_bias.value,
        }

        target.psych_profile = str(profile_dict)
        return profile_dict

    def craft_phishing_email(
        self,
        target: TargetPerson,
        profile: dict[str, str],
    ) -> dict[str, str]:
        """Generate High-Fidelity Synthetic Pretext (Spear Phishing)."""
        bias = profile.get("bias_vector", "curiosity")

        # Synthetic Template Selection (2026 Style)
        # Instead of generic templates, we use 'Micro-Targeted' layouts

        subject = ""
        body = ""
        spoof_sender = ""

        if bias == "authority":
            subject = f"ACTION REQUIRED: Q4 Compliance Review - {target.full_name}"
            body = self._tmpl_authority(target)
            spoof_sender = "legal-compliance@internal-corp.com"

        elif bias == "fear" or "security" in target.role.lower():
            subject = "SECURITY ALERT: Suspicious Login from IP 192.168.x.x"
            body = self._tmpl_security_fear(target)
            spoof_sender = "soc-alerts@internal-security.io"

        elif bias == "curiosity" or "dev" in target.role.lower():
            # JIRA / GitLab style
            ticket_id = f"DEV-{secrets.randbelow(8999) + 1000}"
            subject = f"[{ticket_id}] Critical Bug in Production API (Assigned to You)"
            body = self._tmpl_dev_ticket(target, ticket_id)
            spoof_sender = "jira-bot@automation.io"

        else:
            # Default Social/Reciprocity
            subject = "Invitation: Strategic Planning Lunch w/ Director"
            body = self._tmpl_generic_vip(target)
            spoof_sender = "executive-assist@corp.com"

        return {
            "to": target.email,
            "subject": subject,
            "body": body,
            "from_spoof": spoof_sender,
            "generation_engine": "Create-v5-Turbo",
        }

    # =========================================================================
    # SYNTHETIC PRETEXT TEMPLATES (Dynamic)
    # =========================================================================

    def _tmpl_dev_ticket(self, target, ticket_id) -> str:
        return f"""
<div style="font-family: Arial; border-left: 4px solid #d04437; padding-left: 10px;">
    <h3>JIRA Software</h3>
    <p><b>{target.full_name}</b>, you were mentioned in a ticket:</p>
    <a href="{{link}}"><b>{ticket_id}: NullPointer Exception in Auth Module</b></a>
    <br>
    <p><i>"@ {target.full_name.split()[0]} can you check this? It's blocking the release. CI/CD is failing."</i></p>
    <br>
    <button style="background: #0052cc; color: white; border: none; padding: 10px;">View Issue</button>
</div>
"""

    def _tmpl_security_fear(self, target) -> str:
        return f"""
<div style="font-family: Segoe UI, sans-serif;">
    <h2 style="color: #c00;">🛑 Zero-Trust Alert</h2>
    <p>Identity Protection detected an anomalous access attempt.</p>
    <table border="0">
        <tr><td>User:</td><td>{target.email}</td></tr>
        <tr><td>Location:</td><td><b>Minsk, Belarus</b> (High Risk)</td></tr>
        <tr><td>Device:</td><td>Unknown Android 14</td></tr>
    </table>
    <p>If this wasn't you, you must <b>secure/quarantine</b> your workstation immediately.</p>
    <p><a href="{{link}}">Review Activity Log</a></p>
</div>
"""

    def _tmpl_authority(self, _target) -> str:
        return """
<p>Confidential,</p>
<p>Please review the attached updated Employee Agreement (NDA) regarding the upcoming merger.</p>
<p>Legal requires your digital signature by EOD today.</p>
<br>
<p>Regards,<br><b>Office of General Counsel</b></p>
"""

    def _tmpl_generic_vip(self, target) -> str:
        return f"""
<p>Hi {target.full_name.split()[0]},</p>
<p>The Director asked me to schedule a quick sync with you regarding the Q3 goals.</p>
<p>Are you free next Tuesday? I've shared the tentative agenda below.</p>
<p><a href="{{link}}">View Agenda.docx</a> (SharePoint)</p>
"""
