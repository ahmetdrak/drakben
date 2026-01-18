"""
Custom exceptions for DRAKBEN framework
Provides better error handling and debugging
"""


class DrakbenException(Exception):
    """Base exception for all DRAKBEN errors"""
    pass


class TargetException(DrakbenException):
    """Exceptions related to target specification"""
    pass


class ScanException(DrakbenException):
    """Exceptions during scanning operations"""
    pass


class ExploitException(DrakbenException):
    """Exceptions during exploitation"""
    pass


class PayloadException(DrakbenException):
    """Exceptions during payload generation"""
    pass


class DatabaseException(DrakbenException):
    """Exceptions related to database operations"""
    pass


class NetworkException(DrakbenException):
    """Exceptions related to network operations"""
    pass


class AuthenticationException(DrakbenException):
    """Exceptions related to authentication"""
    pass


class ConfigurationException(DrakbenException):
    """Exceptions related to configuration"""
    pass


class APIException(DrakbenException):
    """Exceptions related to API calls"""
    pass


class ValidationException(DrakbenException):
    """Exceptions related to input validation"""
    pass


# Error codes
class ErrorCodes:
    """Standard error codes"""
    SUCCESS = 0
    GENERAL_ERROR = 1
    TARGET_NOT_SET = 10
    INVALID_TARGET = 11
    SCAN_FAILED = 20
    EXPLOIT_FAILED = 30
    PAYLOAD_GENERATION_FAILED = 40
    DATABASE_ERROR = 50
    NETWORK_ERROR = 60
    AUTH_ERROR = 70
    CONFIG_ERROR = 80
    API_ERROR = 90
    VALIDATION_ERROR = 100
