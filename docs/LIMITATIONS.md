# Limitations

Prefunk is a deterministic preflight for common potential exposures and configuration mistakes. It is not a vulnerability scanner, penetration test, certification, or proof that an application is secure.

The current rule pack checks supported UTF-8 text files for selected OpenAI, GitHub, AWS, private-key, public-client variable, wildcard CORS, Firebase, Supabase, and hardcoded-password patterns.

Prefunk does not currently analyze runtime behavior, authentication flows, authorization logic, IDOR, SQL injection, XSS data flow, dependency CVEs, cloud state, Git history, binary content, provider credential validity, comprehensive secret formats, or complete Supabase RLS correctness.

“No matches” means only that no configured pattern matched within inspected content. Unsupported or incomplete coverage is reported separately and returns a non-success CLI status.
