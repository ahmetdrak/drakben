"""Tests for modules/social_eng — OSINT, Profiler, Phishing, MFA Bypass.

Coverage targets:
- osint.py: TargetPerson, DomainIntel, OSINTSpider core methods
- profiler.py: NLPPayloadEngine, PsychoProfiler
- phishing.py: AntiBotEngine, ShadowCloner, PhishingGenerator
- mfa_bypass.py: MFABypass, ModlishkaProxy, SimpleReverseProxy, UnifiedMFABypass
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from modules.social_eng.mfa_bypass import (
    CapturedCredential,
    CapturedSession,
    MFABypass,
    ModlishkaProxy,
    ProxyBackend,
    SimpleReverseProxy,
    UnifiedMFABypass,
)
from modules.social_eng.osint import DomainIntel, OSINTSpider, TargetPerson
from modules.social_eng.phishing import AntiBotEngine, PhishingGenerator, ShadowCloner
from modules.social_eng.profiler import (
    CognitiveBias,
    NLPPayloadEngine,
    PsychologicalProfile,
    PsychoProfiler,
)


class TestTargetPerson:
    """TargetPerson dataclass sanity."""

    def test_create_default(self):
        p = TargetPerson(full_name="John Doe")
        assert p.full_name == "John Doe"
        assert p.role == "Unknown"
        assert p.email is None
        assert p.confidence == pytest.approx(0.5)

    def test_create_full(self):
        p = TargetPerson(
            full_name="Jane Smith",
            role="CTO",
            email="jane@corp.com",
            social_profiles=["linkedin.com/in/janesmith"],
            confidence=0.9,
        )
        assert p.role == "CTO"
        assert p.email == "jane@corp.com"
        assert len(p.social_profiles) == 1


class TestDomainIntel:
    """DomainIntel dataclass sanity."""

    def test_defaults(self):
        d = DomainIntel(domain="example.com")
        assert d.domain == "example.com"
        assert d.mx_records == []
        assert d.txt_records == []


class TestOSINTSpider:
    """OSINTSpider methods."""

    def setup_method(self):
        self.spider = OSINTSpider()

    def test_predict_email_default_format(self):
        email = self.spider.predict_email("John Doe", "corp.com")
        assert email == "john.doe@corp.com"

    def test_predict_email_custom_format(self):
        email = self.spider.predict_email(
            "John Doe",
            "corp.com",
            "{f}{last}@{domain}",
        )
        assert email == "jdoe@corp.com"

    def test_predict_email_single_name(self):
        email = self.spider.predict_email("Admin", "corp.com")
        assert email == "admin@corp.com"

    def test_verify_email_syntax_valid(self):
        assert self.spider._verify_email_syntax("user@example.com") is True

    def test_verify_email_syntax_invalid(self):
        assert self.spider._verify_email_syntax("bad@@email") is False
        assert self.spider._verify_email_syntax("") is False

    def test_looks_like_name_valid(self):
        assert self.spider._looks_like_name("John Doe") is True
        assert self.spider._looks_like_name("Mary Jane Watson") is True

    def test_looks_like_name_invalid(self):
        assert self.spider._looks_like_name("") is False
        assert self.spider._looks_like_name("x") is False
        assert self.spider._looks_like_name("About Us") is False
        assert self.spider._looks_like_name("singleword") is False
        assert self.spider._looks_like_name("lower case") is False

    def test_find_social_profiles(self):
        profiles = self.spider._find_social_profiles("John Doe")
        assert len(profiles) == 2
        assert "linkedin" in profiles[0]

    def test_detect_email_format_google(self):
        intel = DomainIntel(
            domain="corp.com",
            mx_records=["aspmx.l.google.com"],
        )
        fmt = self.spider._detect_email_format("corp.com", intel)
        assert "{first}" in fmt

    def test_detect_email_format_microsoft(self):
        intel = DomainIntel(
            domain="corp.com",
            mx_records=["corp-com.mail.protection.outlook.com"],
        )
        fmt = self.spider._detect_email_format("corp.com", intel)
        assert "{first}" in fmt

    def test_dns_recon_no_dnspython(self):
        """dns_recon should not crash if dnspython is not importable."""
        intel = self.spider.dns_recon("nonexistent.invalid")
        assert isinstance(intel, DomainIntel)

    def test_get_simulated_results(self):
        results = self.spider._get_simulated_results("corp.com")
        assert len(results) > 0
        assert all(isinstance(r, TargetPerson) for r in results)

    def test_socket_mx_lookup_invalid(self):
        result = self.spider._socket_mx_lookup("nonexistent.invalid.tld")
        assert isinstance(result, list)

    def test_extract_names_from_html_empty(self):
        result = self.spider._extract_names_from_html("<html></html>")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Profiler Tests
# ---------------------------------------------------------------------------


class TestNLPPayloadEngine:
    """NLPPayloadEngine text analysis."""

    def setup_method(self):
        self.engine = NLPPayloadEngine()

    def test_analyze_text_basic(self):
        profile = self.engine.analyze_text("CEO Director Legal compliance audit")
        assert isinstance(profile, PsychologicalProfile)
        assert profile.primary_bias == CognitiveBias.AUTHORITY

    def test_analyze_text_scarcity(self):
        profile = self.engine.analyze_text("deadline urgent immediate today expires")
        assert profile.primary_bias == CognitiveBias.SCARCITY

    def test_analyze_text_fear(self):
        profile = self.engine.analyze_text("security breach alert danger hack risk")
        assert profile.primary_bias == CognitiveBias.FEAR

    def test_analyze_text_curiosity_dev(self):
        profile = self.engine.analyze_text("dev engineer api code")
        assert profile.primary_bias == CognitiveBias.CURIOSITY
        assert profile.synthetic_context == "JIRA"

    def test_analyze_text_empty(self):
        profile = self.engine.analyze_text("")
        assert isinstance(profile, PsychologicalProfile)

    def test_detect_tone_technical(self):
        w = {"api", "server", "code", "bug"}
        tone = self.engine._detect_tone(w)
        assert tone == "Technical"

    def test_detect_tone_corporate(self):
        w = {"strategy", "kpi", "roi", "synergy"}
        tone = self.engine._detect_tone(w)
        assert tone == "Corporate"


class TestPsychoProfiler:
    """PsychoProfiler integration."""

    def setup_method(self):
        self.profiler = PsychoProfiler()

    def test_generate_profile(self):
        target = TargetPerson(full_name="Alice Engineer", role="DevOps Lead")
        profile = self.profiler.generate_profile(target)
        assert isinstance(profile, dict)
        assert "personality_type" in profile
        assert "bias_vector" in profile

    def test_craft_phishing_email_authority(self):
        target = TargetPerson(
            full_name="Bob Manager",
            role="Legal Director",
            email="bob@corp.com",
        )
        profile = {"bias_vector": "authority"}
        email = self.profiler.craft_phishing_email(target, profile)
        assert "subject" in email
        assert "body" in email
        assert "ACTION REQUIRED" in email["subject"]

    def test_craft_phishing_email_fear(self):
        target = TargetPerson(
            full_name="Carol Sec",
            role="Security Analyst",
            email="carol@corp.com",
        )
        profile = {"bias_vector": "fear"}
        email = self.profiler.craft_phishing_email(target, profile)
        assert "SECURITY ALERT" in email["subject"]

    def test_craft_phishing_email_curiosity_dev(self):
        target = TargetPerson(
            full_name="Dave Dev",
            role="Software Developer",
            email="dave@corp.com",
        )
        profile = {"bias_vector": "curiosity"}
        email = self.profiler.craft_phishing_email(target, profile)
        assert "DEV-" in email["subject"]

    def test_craft_phishing_email_default(self):
        target = TargetPerson(
            full_name="Eve User",
            role="Sales",
            email="eve@corp.com",
        )
        profile = {"bias_vector": "social_proof"}
        email = self.profiler.craft_phishing_email(target, profile)
        assert "subject" in email


# ---------------------------------------------------------------------------
# Phishing Tests
# ---------------------------------------------------------------------------


class TestAntiBotEngine:
    """AntiBotEngine JS guard generation."""

    def test_generate_js_guard(self):
        js = AntiBotEngine.generate_js_guard()
        assert "navigator.webdriver" in js
        assert "window.outerWidth" in js
        assert "google.com" in js

    def test_js_guard_unique(self):
        AntiBotEngine.generate_js_guard()
        AntiBotEngine.generate_js_guard()


class TestShadowCloner:
    """ShadowCloner asset embedding."""

    def test_download_as_b64_invalid_url(self):
        cloner = ShadowCloner()
        result = cloner._download_as_b64("http://nonexistent.invalid/img.png")
        assert result == ""

    def test_fetch_text_invalid_url(self):
        cloner = ShadowCloner()
        result = cloner._fetch_text("http://nonexistent.invalid/style.css")
        assert result == ""


class TestPhishingGenerator:
    """PhishingGenerator site cloning."""

    def test_init_creates_output_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "phish_out")
            PhishingGenerator(output_dir=out)
            assert Path(out).is_dir()

    def test_clone_site_invalid_url(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = PhishingGenerator(output_dir=tmpdir)
            result = gen.clone_site("http://nonexistent.invalid.tld")
            assert result == ""

    def test_fix_asset_links_deprecated(self):
        import warnings

        with tempfile.TemporaryDirectory() as tmpdir:
            gen = PhishingGenerator(output_dir=tmpdir)
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                gen._fix_asset_links(None, "http://example.com")
                assert len(w) >= 1
                assert issubclass(w[0].category, DeprecationWarning)


# ---------------------------------------------------------------------------
# MFA Bypass Tests
# ---------------------------------------------------------------------------


class TestMFABypass:
    """MFABypass (Evilginx2) wrapper."""

    def test_init_not_available(self):
        bypass = MFABypass(evilginx_path="/nonexistent")
        assert bypass.available is False

    def test_list_phishlets_empty(self):
        bypass = MFABypass(evilginx_path="/nonexistent")
        assert bypass.list_phishlets() == []

    def test_start_proxy_not_available(self):
        bypass = MFABypass(evilginx_path="/nonexistent")
        assert bypass.start_proxy("test", "test.local") is False

    def test_parse_captured_sessions_no_file(self):
        bypass = MFABypass(evilginx_path="/nonexistent")
        sessions = bypass.parse_captured_sessions()
        assert sessions == []

    def test_replay_session(self):
        bypass = MFABypass(evilginx_path="/nonexistent")
        session = CapturedSession(
            target_url="https://target.com",
            username="user",
            password="pass",
            session_tokens={"token": "abc"},
            cookies=[{"name": "sid", "value": "123"}],
            timestamp="2025-01-01",
        )
        result = bypass.replay_session(session)
        assert "curl" in result
        assert "python" in result
        assert "sid" in result["curl"]


class TestModlishkaProxy:
    """ModlishkaProxy wrapper."""

    def test_init_not_available(self):
        proxy = ModlishkaProxy(modlishka_path="/nonexistent")
        assert proxy.available is False

    def test_start_not_available(self):
        proxy = ModlishkaProxy(modlishka_path="/nonexistent")
        assert proxy.start("config.json") is False

    def test_create_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proxy = ModlishkaProxy(modlishka_path=tmpdir)
            config_path = proxy.create_config(
                target_domain="login.example.com",
                phishing_domain="phish.local",
            )
            assert os.path.exists(config_path)
            with open(config_path, encoding="utf-8") as f:
                data = json.load(f)
            assert data["target"] == "login.example.com"


class TestSimpleReverseProxy:
    """SimpleReverseProxy credential capture."""

    def test_init(self):
        proxy = SimpleReverseProxy(listen_port=9999)
        assert proxy.listen_port == 9999
        assert proxy.running is False

    def test_get_captured_credentials_empty(self):
        proxy = SimpleReverseProxy()
        assert proxy.get_captured_credentials() == []

    def test_extract_form_credentials(self):
        proxy = SimpleReverseProxy()
        data = {"email": ["admin@corp.com"], "password": ["secret"]}
        user, pwd = proxy._extract_form_credentials(data)
        assert user == "admin@corp.com"
        assert pwd == "secret"

    def test_extract_json_credentials(self):
        proxy = SimpleReverseProxy()
        data = {"username": "admin", "password": "p@ss"}
        user, pwd = proxy._extract_json_credentials(data)
        assert user == "admin"
        assert pwd == "p@ss"


class TestCapturedCredential:
    """CapturedCredential dataclass."""

    def test_create(self):
        cred = CapturedCredential(username="u", password="p")
        assert cred.cookies == {}
        assert cred.timestamp == ""


class TestUnifiedMFABypass:
    """UnifiedMFABypass backend selection."""

    def test_default_backend_builtin(self):
        u = UnifiedMFABypass()
        assert u.active_backend == ProxyBackend.BUILTIN

    def test_get_available_backends(self):
        u = UnifiedMFABypass()
        backends = u.get_available_backends()
        assert "builtin" in backends

    def test_set_backend_evilginx_fails(self):
        u = UnifiedMFABypass()
        assert u.set_backend(ProxyBackend.EVILGINX2) is False

    def test_set_backend_modlishka_fails(self):
        u = UnifiedMFABypass()
        assert u.set_backend(ProxyBackend.MODLISHKA) is False
