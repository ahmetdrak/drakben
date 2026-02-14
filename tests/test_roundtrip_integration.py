"""DRAKBEN Roundtrip Integration Tests.

Validates end-to-end correctness of real implementations:
- Stego embed/extract roundtrip
- AES-256-GCM encrypt/decrypt roundtrip
- Singularity code generation (all templates)
- Symbolic executor heuristic solver
- CVE fetcher NVD integration path
- Phishing campaign config validation
- SRE evolution multi-step
- VectorStore write/search
"""

import ast
import os
import struct
import tempfile
import zlib

import pytest

# ---------------------------------------------------------------------------
# 1. Stego Transport: Embed → Extract roundtrip
# ---------------------------------------------------------------------------

class TestStegoRoundtrip:
    """Test steganographic data embedding/extraction cycle."""

    def _make_minimal_png(self) -> bytes:
        """Create a minimal valid PNG file (1x1 white pixel)."""
        # PNG signature
        sig = b"\x89PNG\r\n\x1a\n"

        # IHDR chunk
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)  # 1x1, 8-bit RGB
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data).to_bytes(4, "big")
        ihdr = len(ihdr_data).to_bytes(4, "big") + b"IHDR" + ihdr_data + ihdr_crc

        # IDAT chunk (compressed pixel data: filter byte 0 + RGB white)
        raw_data = zlib.compress(b"\x00\xff\xff\xff")
        idat_crc = zlib.crc32(b"IDAT" + raw_data).to_bytes(4, "big")
        idat = len(raw_data).to_bytes(4, "big") + b"IDAT" + raw_data + idat_crc

        # IEND chunk
        iend_crc = zlib.crc32(b"IEND").to_bytes(4, "big")
        iend = (0).to_bytes(4, "big") + b"IEND" + iend_crc

        return sig + ihdr + idat + iend

    def test_chunk_injection_roundtrip(self):
        """Embed data via chunk injection and extract it back."""
        from modules.c2_framework import StegoTransport

        secret = b"DRAKBEN_C2_SECRET_DATA_2026"

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(self._make_minimal_png())
            png_path = f.name

        try:
            modified_png = StegoTransport.embed_data(png_path, secret)
            assert modified_png, "embed_data returned empty"

            extracted = StegoTransport.extract_data(modified_png)
            assert extracted == secret, f"Expected {secret!r}, got {extracted!r}"
        finally:
            os.unlink(png_path)

    def test_empty_data_roundtrip(self):
        """Roundtrip with empty payload should not crash."""
        from modules.c2_framework import StegoTransport

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(self._make_minimal_png())
            png_path = f.name

        try:
            modified = StegoTransport.embed_data(png_path, b"")
            assert modified is not None
        finally:
            os.unlink(png_path)


# ---------------------------------------------------------------------------
# 2. AES-256-GCM Encrypt → Decrypt roundtrip
# ---------------------------------------------------------------------------

class TestAESGCMRoundtrip:
    """Test AES-256-GCM encryption/decryption cycle used by C2Channel."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt data and decrypt it back — must match original."""
        from modules.c2_framework import C2Channel, C2Config, C2Protocol

        config = C2Config(
            primary_host="127.0.0.1",
            primary_port=443,
            protocol=C2Protocol.HTTPS,
            encryption_key=b"test_key_for_roundtrip_validation",
        )
        channel = C2Channel(config)

        original = b'{"cmd": "sleep", "interval": 30}'
        encrypted = channel._encrypt(original)

        assert encrypted != original, "Encrypted should differ from plaintext"
        assert len(encrypted) > 0

        decrypted = channel._decrypt(encrypted)
        assert decrypted == original, f"Expected {original!r}, got {decrypted!r}"

    def test_different_keys_fail(self):
        """Decryption with wrong key should return empty bytes."""
        from modules.c2_framework import C2Channel, C2Config, C2Protocol

        config1 = C2Config(
            primary_host="127.0.0.1", primary_port=443, protocol=C2Protocol.HTTPS,
            encryption_key=b"key_one",
        )
        config2 = C2Config(
            primary_host="127.0.0.1", primary_port=443, protocol=C2Protocol.HTTPS,
            encryption_key=b"key_two",
        )

        ch1 = C2Channel(config1)
        ch2 = C2Channel(config2)

        encrypted = ch1._encrypt(b"secret data")
        decrypted = ch2._decrypt(encrypted)

        # Should fail verification and return empty
        assert decrypted == b"", "Wrong key should not decrypt successfully"

    def test_large_payload(self):
        """Roundtrip with a large payload (100 KB)."""
        from modules.c2_framework import C2Channel, C2Config, C2Protocol

        config = C2Config(
            primary_host="127.0.0.1", primary_port=443, protocol=C2Protocol.HTTPS,
            encryption_key=b"bulk_test_key",
        )
        channel = C2Channel(config)

        large_data = os.urandom(100_000)
        encrypted = channel._encrypt(large_data)
        decrypted = channel._decrypt(encrypted)

        assert decrypted == large_data


# ---------------------------------------------------------------------------
# 3. Singularity: Code generation templates produce valid Python
# ---------------------------------------------------------------------------

class TestSingularityTemplates:
    """Verify all mock LLM templates produce syntactically valid code."""

    PROMPTS = [
        ("port scanner tool", "scanner"),
        ("subdomain enumerator", "subdomain"),
        ("HTTP header checker", "header"),
        ("directory brute-forcer", "dir"),
        ("DNS record resolver", "dns"),
        ("TCP banner grabber", "banner"),
        ("something completely unknown", "generic"),
    ]

    @pytest.mark.parametrize("prompt,label", PROMPTS)
    def test_template_syntax(self, prompt, label):
        """Each template must produce parseable Python code."""
        from core.singularity.synthesizer import CodeSynthesizer

        synth = CodeSynthesizer()
        code = synth._mock_llm_call(prompt, "python")

        assert code, f"Template '{label}' returned empty code"
        assert "# Placeholder code for:" not in code, (
            f"Template '{label}' returned generic placeholder"
        )

        # Must parse as valid Python
        try:
            ast.parse(code)
        except SyntaxError as e:
            pytest.fail(f"Template '{label}' generated invalid Python: {e}")

    def test_generate_tool_returns_snippet(self):
        """generate_tool should return CodeSnippet with validated code."""
        from core.singularity.synthesizer import CodeSynthesizer

        synth = CodeSynthesizer()
        snippet = synth.generate_tool("port scanner with banner grabbing", "python")

        assert snippet.code, "CodeSnippet.code is empty"
        assert snippet.language == "python"
        assert snippet.purpose == "port scanner with banner grabbing"

    def test_refactor_removes_unused_imports(self):
        """refactor_code should remove unused imports."""
        from core.singularity.synthesizer import CodeSynthesizer

        synth = CodeSynthesizer()
        code = "import os\nimport sys\nprint(os.getcwd())\n"
        result = synth.refactor_code(code)

        assert "sys" not in result.code, "Unused 'sys' import should be removed"
        assert "os" in result.code, "'os' is used and should remain"
        assert result.is_validated is True


# ---------------------------------------------------------------------------
# 4. Symbolic Executor: Heuristic boundary solver
# ---------------------------------------------------------------------------

class TestSymbolicHeuristic:
    """Verify boundary-aware heuristic solver produces correct values."""

    def test_equality_constraint(self):
        """== constraint must return exact value."""
        from modules.research.symbolic import ExecutionPath, PathConstraint, SymbolicExecutor

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.z3_available = False

        path = ExecutionPath(
            path_id=1,
            constraints=[PathConstraint("x", "==", 42)],
            reaches_sink=True,
        )
        result = executor._heuristic_solve(path)
        assert result["x"] == 42

    def test_gt_constraint(self):
        """> constraint must produce value above threshold."""
        from modules.research.symbolic import ExecutionPath, PathConstraint, SymbolicExecutor

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.z3_available = False

        path = ExecutionPath(
            path_id=2,
            constraints=[PathConstraint("x", ">", 10)],
            reaches_sink=True,
        )
        result = executor._heuristic_solve(path)
        assert result["x"] > 10, f"Expected >10, got {result['x']}"

    def test_lt_constraint(self):
        """< constraint must produce value below threshold."""
        from modules.research.symbolic import ExecutionPath, PathConstraint, SymbolicExecutor

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.z3_available = False

        path = ExecutionPath(
            path_id=3,
            constraints=[PathConstraint("x", "<", 5)],
            reaches_sink=True,
        )
        result = executor._heuristic_solve(path)
        assert result["x"] < 5, f"Expected <5, got {result['x']}"

    def test_ne_constraint(self):
        """!= constraint must produce value different from given."""
        from modules.research.symbolic import ExecutionPath, PathConstraint, SymbolicExecutor

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.z3_available = False

        path = ExecutionPath(
            path_id=4,
            constraints=[PathConstraint("x", "!=", 100)],
            reaches_sink=True,
        )
        result = executor._heuristic_solve(path)
        assert result["x"] != 100, f"Expected !=100, got {result['x']}"

    def test_multiple_constraints(self):
        """Multiple constraints produce correct results for each variable."""
        from modules.research.symbolic import ExecutionPath, PathConstraint, SymbolicExecutor

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.z3_available = False

        path = ExecutionPath(
            path_id=5,
            constraints=[
                PathConstraint("x", ">", 0),
                PathConstraint("y", "==", 7),
            ],
            reaches_sink=True,
        )
        result = executor._heuristic_solve(path)
        assert result["x"] > 0
        assert result["y"] == 7


# ---------------------------------------------------------------------------
# 5. CVE Fetcher: NVD integration path
# ---------------------------------------------------------------------------

class TestCVEFetcher:
    """Test exploit fetcher with known and unknown CVEs."""

    @pytest.mark.asyncio
    async def test_known_cve_found(self):
        """Known CVE (Log4Shell) should return success."""
        from modules.exploit import fetch_and_prepare_exploit

        # Create a minimal mock state
        class MockState:
            pass

        state = MockState()
        result = await fetch_and_prepare_exploit(state, "CVE-2021-44228")

        assert result["success"] is True
        assert result["description"] == "Log4Shell"
        assert "exploit_file" in result

    @pytest.mark.asyncio
    async def test_unknown_cve_returns_recommendation(self):
        """Unknown CVE should gracefully return recommendation."""
        from modules.exploit import fetch_and_prepare_exploit

        class MockState:
            pass

        state = MockState()
        result = await fetch_and_prepare_exploit(state, "CVE-9999-99999")

        assert result["success"] is False
        assert "recommendation" in result

    @pytest.mark.asyncio
    async def test_expanded_known_cves(self):
        """Check that newly added CVEs (ActiveMQ, Confluence, PAN-OS) are available."""
        from unittest.mock import patch

        from modules.exploit import fetch_and_prepare_exploit

        class MockState:
            pass

        state = MockState()

        # Patch CVEDatabase at the source module to avoid network calls
        with patch("modules.cve_database.CVEDatabase", side_effect=Exception("skip NVD")):
            for cve_id in ("CVE-2023-44228", "CVE-2023-22515", "CVE-2024-3400"):
                result = await fetch_and_prepare_exploit(state, cve_id)
                assert result["success"] is True, f"{cve_id} should be in local PoC bank"

    @pytest.mark.asyncio
    async def test_null_state_rejected(self):
        """Null state must be rejected."""
        from modules.exploit import fetch_and_prepare_exploit

        result = await fetch_and_prepare_exploit(None, "CVE-2021-44228")
        assert result["success"] is False


# ---------------------------------------------------------------------------
# 6. Phishing Campaign: Config validation
# ---------------------------------------------------------------------------

class TestPhishingCampaign:
    """Test generate_campaign validation (no real SMTP)."""

    def test_missing_smtp_config(self):
        """Without SMTP env vars, campaign should fail gracefully."""
        from modules.social_eng.phishing import PhishingGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            gen = PhishingGenerator(output_dir=tmpdir)

            # Ensure SMTP vars are not set
            env_backup = {}
            for key in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS"):
                env_backup[key] = os.environ.pop(key, None)

            try:
                result = gen.generate_campaign(
                    ["test@example.com"], "nonexistent_template",
                )
                assert result["success"] is False
                assert "SMTP not configured" in result["error"]
            finally:
                for key, val in env_backup.items():
                    if val is not None:
                        os.environ[key] = val

    def test_missing_template(self):
        """With SMTP configured but missing template, should fail."""
        from modules.social_eng.phishing import PhishingGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            gen = PhishingGenerator(output_dir=tmpdir)

            os.environ["SMTP_HOST"] = "localhost"
            os.environ["SMTP_USER"] = "test"
            os.environ["SMTP_PASS"] = "pass"

            try:
                result = gen.generate_campaign(
                    ["test@example.com"], "missing_template",
                )
                assert result["success"] is False
                assert "Template not found" in result["error"]
            finally:
                os.environ.pop("SMTP_HOST", None)
                os.environ.pop("SMTP_USER", None)
                os.environ.pop("SMTP_PASS", None)


# ---------------------------------------------------------------------------
# 7. VectorStore: Write → Search roundtrip
# ---------------------------------------------------------------------------

class TestVectorStoreRoundtrip:
    """Test ChromaDB vector store write/search cycle."""

    def test_add_and_search(self):
        """Add a memory and search for it."""
        from core.storage.vector_store import DEPENDENCIES_AVAILABLE, VectorStore

        if not DEPENDENCIES_AVAILABLE:
            pytest.skip("ChromaDB not available")

        tmpdir = tempfile.mkdtemp()
        try:
            store = VectorStore(persist_dir=tmpdir)

            success = store.add_memory(
                "Found open port 443 on target 10.0.0.1",
                metadata={"type": "recon"},
            )
            assert success is True

            results = store.search("open port", n_results=1)
            assert len(results) >= 1
            assert "443" in results[0]["text"]

            # Explicitly release ChromaDB resources
            store.close()
            del store
        except ImportError:
            pytest.skip("ChromaDB import failed")
        # Don't try to remove tmpdir — ChromaDB locks files on Windows

    def test_search_empty_store(self):
        """Search on empty store should return empty list."""
        from core.storage.vector_store import DEPENDENCIES_AVAILABLE, VectorStore

        if not DEPENDENCIES_AVAILABLE:
            pytest.skip("ChromaDB not available")

        tmpdir = tempfile.mkdtemp()
        try:
            store = VectorStore(persist_dir=tmpdir)
            results = store.search("anything", n_results=5)
            assert results == []
            store.close()
            del store
        except ImportError:
            pytest.skip("ChromaDB import failed")


# ---------------------------------------------------------------------------
# 9. DNS Tunneler: Chunk/reassemble roundtrip
# ---------------------------------------------------------------------------

class TestDNSChunking:
    """Test DNS tunneler data chunking logic."""

    def test_chunk_and_reassemble(self):
        """Data chunked and reassembled must match original."""
        from modules.c2_framework import DNSTunneler

        tunneler = DNSTunneler(
            c2_domain="test.example.com",
            dns_server="8.8.8.8",
        )

        original = b"A" * 200
        chunks = tunneler.chunk_data(original, chunk_size=60)

        assert len(chunks) == 4  # 200 bytes / 60 per chunk = 4 chunks

        reassembled = b"".join(chunks)
        assert reassembled == original

    def test_small_data_single_chunk(self):
        """Data smaller than chunk_size produces one chunk."""
        from modules.c2_framework import DNSTunneler

        tunneler = DNSTunneler(c2_domain="t.com", dns_server="8.8.8.8")
        chunks = tunneler.chunk_data(b"small", chunk_size=60)
        assert len(chunks) == 1
        assert chunks[0] == b"small"
