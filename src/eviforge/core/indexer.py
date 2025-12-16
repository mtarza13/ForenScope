import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from datetime import datetime

from eviforge.core.models import Entity, IOC, IOCMatch, Finding, Evidence
from eviforge.config import load_settings

# Regex patterns (Defensive only)
IPV4_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
DOMAIN_PATTERN = r'\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b'
MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'

class Indexer:
    def __init__(self, session: Session):
        self.session = session
        self.settings = load_settings()
        
    def process_text_content(self, text: str, evidence_id: str, case_id: str, source: str = "tika"):
        """
        Extract basic entities from raw text and save to Entities table
        """
        if not text:
            return
            
        entities: List[Entity] = []
        
        # IPS
        for match in re.finditer(IPV4_PATTERN, text):
            ip_str = match.group()
            try:
                ip = ipaddress.ip_address(ip_str)
                if not ip.is_global:
                    continue # Skip private IPs for noise reduction? Or keep? Let's keep public only for now
                entities.append(Entity(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    type="ip",
                    value=str(ip),
                    source_module=source
                ))
            except:
                continue

        # Emails
        for match in re.finditer(EMAIL_PATTERN, text):
            entities.append(Entity(
                case_id=case_id,
                evidence_id=evidence_id,
                type="email",
                value=match.group().lower(),
                source_module=source
            ))

        # Domains
        for match in re.finditer(DOMAIN_PATTERN, text):
            d = match.group().lower()
            if d in ["com", "net", "org"]: continue
            entities.append(Entity(
                case_id=case_id,
                evidence_id=evidence_id,
                type="domain",
                value=d,
                source_module=source
            ))
            
        # Deduplicate locally before insert
        unique_entities = {} # key=(type, value)
        for e in entities:
             unique_entities[(e.type, e.value)] = e
        
        for e in unique_entities.values():
            # Check DB existance? Ideally we want 'last_seen' update if exists
            # For speed MVP, just insert blind and let DB unique constraint handle it? 
            # We don't have unique constraint yet on (case_id, type, value).
            # Let's query first (slow but safe) or upsert.
            
            existing = self.session.query(Entity).filter_by(
                case_id=case_id, type=e.type, value=e.value
            ).first()
            
            if existing:
                existing.last_seen = datetime.utcnow()
                # Link evidence if not already? Many-to-Many would be better but we have 1:N in model currently (evidence_id column).
                # Model actually has evidence_id. So if same entity found in diff evidence, we create new row or update?
                # Definition: Entity row = "Instance of entity in this evidence" vs "Global Entity".
                # Current usage: Log each occurrence? Or distinct entities per case?
                # Let's do distinct entities per case, and evidence_id points to *first_seen* or *most_recent*.
                pass 
            else:
                self.session.add(e)
                
        self.session.commit()
        
    def match_iocs(self, case_id: str):
        """
        Scan all entities in case against IOC table
        """
        iocs = self.session.query(IOC).filter_by(case_id=case_id).all()
        # In memory loop (MVP)
        
        matches_found = 0
        
        for ioc in iocs:
            # Find entities matching
            ents = self.session.query(Entity).filter_by(case_id=case_id, type=ioc.type, value=ioc.value).all()
            for ent in ents:
                # Create Match
                # Check if match exists
                exists = self.session.query(IOCMatch).filter_by(ioc_id=ioc.id, entity_id=ent.id).first()
                if not exists:
                    m = IOCMatch(
                        case_id=case_id,
                        ioc_id=ioc.id,
                        entity_id=ent.id,
                        evidence_id=ent.evidence_id,
                        module="indexer"
                    )
                    self.session.add(m)
                    matches_found += 1
                    
                    # Create Finding
                    f = Finding(
                        case_id=case_id,
                        title=f"IOC Match: {ioc.value} ({ioc.type})",
                        description=f"Matched high confidence IOC in evidence.",
                        severity="high",
                        status="open",
                        related_entities=ent.id,
                        related_evidence=ent.evidence_id
                    )
                    self.session.add(f)
                    
        self.session.commit()
        return matches_found
