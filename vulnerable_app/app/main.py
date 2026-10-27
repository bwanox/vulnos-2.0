"""VulnerableApp — Intentionally flawed microservice for live demo.

Contains 3 planted vulnerabilities:
1. SQL Injection in user lookup endpoint
2. Post-cutoff vulnerable dependency (for Tavily demo)
3. Tricky patch scenario that breaks existing tests on first naive fix
"""
