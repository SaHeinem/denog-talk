# Anatomy of a securty.txt file

## Required fields:

- Contact: Specifies one or more methods (such as email, web form, or phone number) for reaching the security team. Each contact uses a URI
- Expires: Gives the expiration date for the information, in ISO 8601 format (e.g., "2025-12-31T23:59:59Z"). An expired file should be considered stale.

## Optional Fields

- Encryption: URL of a public encryption key, often for PGP, to enable secure communication.
- Acknowledgments: URL to a page recognizing individuals who reported vulnerabilities.
- Policy: URL describing the organization’s vulnerability disclosure policy.
- Hiring: URL linking to job opportunities related to security roles.
- Canonical: URL pointing to the canonical location of this security.txt file.
- Preferred-Languages: List of preferred languages for communication, comma-separated.

# Additional Details

Each field must appear on its own line. Fields may appear multiple times if appropriate (such as multiple Contact or Preferred-Languages lines).

Comments begin with "#". Blank lines are ignored.

The file must be UTF-8 encoded, served as text/plain, and accessible over HTTPS from /.well-known/security.txt.
