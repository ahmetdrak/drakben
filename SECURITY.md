# Security Policy

## Responsible Use

DRAKBEN is a penetration testing framework designed for **authorized security assessments only**. 

**By using this software, you agree to:**

1. Only use DRAKBEN on systems you own or have explicit written permission to test
2. Comply with all applicable laws and regulations
3. Follow responsible disclosure practices
4. Not use this tool for malicious purposes

## Reporting Security Vulnerabilities

### Scope

We accept vulnerability reports for:

- Security issues in DRAKBEN itself
- Vulnerabilities that could be exploited to compromise a user's system
- Issues that could lead to unauthorized access or data exposure

### Out of Scope

- Issues in third-party tools (nmap, nikto, etc.)
- Theoretical attacks without proof of concept
- Social engineering attacks against DRAKBEN users

### How to Report

**Do NOT create public GitHub issues for security vulnerabilities.**

Instead, please email: **security@drakben.dev** (placeholder)

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Within 30 days (depending on severity)

## Security Features

### Built-in Security

DRAKBEN includes several security features:

| Feature | Description |
|---------|-------------|
| CommandSanitizer | Validates and sanitizes shell commands |
| Ghost Protocol | Memory protection and anti-forensics |
| SSL Verification | Configurable certificate verification |
| LLM Cache Filtering | Filters sensitive data from cache |
| Credential Encryption | Encrypts stored credentials |

### Configuration

Security settings in `config/settings.json`:

```json
{
  "security": {
    "ssl_verify": true,
    "allow_self_signed_certs": false,
    "encrypt_credentials": true,
    "sanitize_commands": true
  }
}
```

### Environment Variables

Sensitive data should be stored in environment variables:

```bash
export OPENROUTER_API_KEY="your-key"
export DRAKBEN_ENCRYPTION_KEY="your-encryption-key"
```

Never commit API keys or credentials to the repository.

## Secure Development

### For Contributors

1. **Never introduce backdoors** - All code is reviewed
2. **Validate all input** - Use CommandSanitizer
3. **Use type annotations** - Mypy catches many bugs
4. **Write tests** - Security features need thorough testing
5. **Document security implications** - Add comments for sensitive code

### Code Review Checklist

- [ ] No hardcoded credentials
- [ ] Input validation present
- [ ] Appropriate error handling
- [ ] No information leakage in error messages
- [ ] Secure defaults used
- [ ] Documentation updated

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. The authors are not responsible for any misuse of this software. Users assume all responsibility for ensuring their use of DRAKBEN complies with all applicable laws.

**Unauthorized access to computer systems is illegal.** Always obtain proper authorization before conducting security assessments.

## Acknowledgments

We thank the security community for responsible vulnerability disclosures.

---

*Last updated: February 4, 2026*
