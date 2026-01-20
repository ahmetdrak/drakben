from dataclasses import dataclass
from enum import Enum


class ApprovalStatus(Enum):
    """Approval status enum"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ApprovalState:
    approved: bool = False
    status: ApprovalStatus = ApprovalStatus.PENDING


class OneTimeApproval:
    def __init__(self):
        self.state = ApprovalState(approved=False)

    def ensure_approved(self, prompt_func) -> bool:
        if self.state.approved:
            return True
        approved = prompt_func()
        if approved:
            self.state.approved = True
            self.state.status = ApprovalStatus.APPROVED
        else:
            self.state.status = ApprovalStatus.REJECTED
        return approved


# Alias for backward compatibility
ApprovalFlow = OneTimeApproval
