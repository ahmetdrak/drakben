"""
DRAKBEN Social Engineering - Psycho Profiler
Author: @drak_ben
Description: Uses LLM to generate psychological profiles and phishing scenarios.
"""

import logging
from typing import Dict, Any, Optional
from .osint import TargetPerson

logger = logging.getLogger(__name__)

class PsychoProfiler:
    """
    Analyzes target traits to recommend influence strategies.
    Principles: Authority, Urgency, Curiosity, Fear, Greed.
    """
    
    def __init__(self, llm_provider=None):
        self.llm = llm_provider
        self.strategies = {
            "IT Administrator": {"hook": "Technical Alert", "emotion": "Fear/Responsibility"},
            "HR Manager": {"hook": "CV/Resume", "emotion": "Curiosity/Duty"},
            "Finance Director": {"hook": "Invoice Overdue", "emotion": "Urgency/Fear"},
            "CEO": {"hook": "Legal Complaint", "emotion": "Authority/Fear"}
        }
        logger.info("PsychoProfiler initialized")
        
    def generate_profile(self, target: TargetPerson) -> Dict[str, str]:
        """
        Generate a psychological profile and attack strategy.
        """
        logger.info(f"Profiling target: {target.full_name} ({target.role})")
        
        # 1. LLM Approach (If available)
        if self.llm:
            try:
                # Placeholder for LLM call
                # prompt = f"Analyze {target.role} and suggest a phishing email topic."
                pass
            except Exception:
                pass
                
        # 2. Heuristic Approach (Fallback)
        strategy = self.strategies.get(target.role, {"hook": "General Update", "emotion": "Curiosity"})
        
        profile = {
            "personality_type": "Analytical" if "IT" in target.role or "Finance" in target.role else "Social",
            "recommended_lure": strategy["hook"],
            "emotional_trigger": strategy["emotion"],
            "best_time_to_send": "09:15 AM (Tuesday)",
            "tone": "Formal"
        }
        
        target.psych_profile = str(profile)
        return profile

    def craft_phishing_email(self, target: TargetPerson, profile: Dict[str, str]) -> Dict[str, str]:
        """
        Generate the actual email content based on profile.
        """
        lure = profile["recommended_lure"]
        
        subject = f"ACTION REQUIRED: {lure} - Ref#99283"
        
        if lure == "Technical Alert":
            body = f"""Dear {target.full_name},
            
We have detected unusual activity on your account registered to {target.email}.
Per company policy, please verify your credentials immediately to avoid lockout.

[Link: Verify Now]

IT Security Team
"""
        elif lure == "Invoice Overdue":
            body = f"""Dear {target.full_name},
            
Attached is the overdue invoice INV-2024-001. Please process payment immediately to avoid service interruption.

Regards,
Vendor Accounts
"""
        else:
            body = f"""Hi {target.full_name.split()[0]},
            
Please check the attached document regarding the Q1 operational changes.

Best,
Management
"""
        
        return {
            "to": target.email,
            "subject": subject,
            "body": body,
            "from_spoof": "security@internal-alert.com"
        }
