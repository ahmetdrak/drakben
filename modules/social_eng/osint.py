"""
DRAKBEN Social Engineering - OSINT Spider
Author: @drak_ben
Description: Gathers target intelligence (personnel, emails) from public sources.
"""

import logging
import random
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TargetPerson:
    """Represents a human target"""

    full_name: str
    role: str = "Unknown"
    email: Optional[str] = None
    social_profiles: Optional[List[str]] = None
    psych_profile: Optional[str] = None


class OSINTSpider:
    """
    Crawls open sources to build a target list.
    """

    def __init__(self):
        self.common_formats = [
            "{first}.{last}@{domain}",
            "{first}{last}@{domain}",
            "{f}{last}@{domain}",
            "{first}.{l}@{domain}",
        ]
        logger.info("OSINT Spider initialized")

    def harvest_domain(self, domain: str) -> List[TargetPerson]:
        """
        Main entry point: Harvest targets from a company domain.
        Uses search engines and public lookups (simulated hooks).
        """
        logger.info(f"Harvesting intelligence for: {domain}")
        targets = []

        # 1. Search Engine Recon (Simulation of Google Dorking)
        # "site:linkedin.com/in/ 'Company Name'"
        # In a real tool, this would use a SERP API (Serper, SerpApi, or custom scraper)
        # Here we mock realistic results for demonstration if no API key provided

        simulated_names = [
            ("John Doe", "IT Administrator"),
            ("Jane Smith", "HR Manager"),
            ("Robert Brown", "Finance Director"),
            ("Emily White", "Security Analyst"),
        ]

        for name, role in simulated_names:
            email = self.predict_email(name, domain)
            targets.append(
                TargetPerson(
                    full_name=name,
                    role=role,
                    email=email,
                    social_profiles=[
                        f"linkedin.com/in/{name.lower().replace(' ', '')}"
                    ],
                )
            )

        logger.info(f"Found {len(targets)} potential targets")
        return targets

    def predict_email(
        self, full_name: str, domain: str, format_str: str = "{first}.{last}@{domain}"
    ) -> str:
        """
        Predict email address based on name and domain.
        """
        try:
            parts = full_name.lower().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                f_initial, l_initial = first[0], last[0]

                # Use a specific format or default
                email = format_str.format(
                    first=first, last=last, f=f_initial, l=l_initial, domain=domain
                )
                return email
            return f"{parts[0]}@{domain}"
        except Exception as e:
            logger.error(f"Email prediction error: {e}")
            return ""

    def search_leaked_credentials(self, email: str) -> bool:
        """Check if email appears in known breaches (Mock: HaveIBeenPwned)"""
        # Placeholder for HIBP API
        return random.random() < 0.3  # 30% chance of leak
