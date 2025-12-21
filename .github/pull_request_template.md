## Description

<!-- Briefly describe what this PR does -->

## Type of Change

- [ ] New security rules
- [ ] Rule updates/corrections
- [ ] Bug fix
- [ ] Documentation
- [ ] CI/CD or infrastructure
- [ ] Other (describe below)

## Checklist

### For Rule Changes

- [ ] Rules follow the Do/Don't/Why/Refs format
- [ ] Code examples are copy-paste ready and tested
- [ ] Enforcement levels are appropriate (strict/warning/advisory)
- [ ] At least one authoritative reference included (CWE, OWASP, NIST)
- [ ] Quick Reference table updated (if adding new rules)
- [ ] Prerequisites section links to relevant core rules

### For All Changes

- [ ] I have read [CONTRIBUTING.md](docs/CONTRIBUTING.md)
- [ ] Tests pass locally (`pytest tests/`)
- [ ] No sensitive data in examples (passwords, API keys)
- [ ] Markdown formatting is correct

## Standards Coverage

<!-- If adding new rules, list the standards they map to -->

| Standard | Reference |
|----------|----------|
| CWE | CWE-XXX |
| OWASP | A0X:2025 |
| NIST | NIST 800-53 XX-X |

## Testing

<!-- Describe any testing performed -->

- [ ] Ran `pytest tests/structural/` - format validation
- [ ] Ran `pytest tests/code_validation/` - code syntax
- [ ] Verified code examples work as documented

## Related Issues

<!-- Link any related issues: Fixes #123, Relates to #456 -->

## Additional Notes

<!-- Any other context reviewers should know -->
