# Security & Architecture

## Security Model

EviForge is designed for **LOCAL** use but includes controls for "Bastion Host" deployment.

### Authentication
- **Admin Token**: Automated access via `X-Admin-Token` header.
- **Web Login**: Secure HTTPOnly Cookie (JWT).

### Authorization
- **Admin**: Full system access.
- **User**: Case operations only (future roadmap).

### Chain of Custody
Every action (Ingest, Job Run, Export) is cryptographically logged in `chain_of_custody.log` and the Database.
- **Prev Hash**: Links to previous event.
- **Integrity**: Cannot delete logs without breaking chain.

## Privacy (OSINT)
The **Optimization for Open Source Intelligence (OSINT)** module is strictly LIMITED:
- **Defensive Use**: Tracking "Opt-Out" requests only.
- **No Scrapers**: No tools to scrape social media or breach ToS.
