"""Conservative linkage of explicitly associated internal patient and encounter IDs.
No fuzzy identity search, external registry, or demographic matching.
"""
from collections import defaultdict
from crypto import pseudonym, token
from privacy import norm, evidence
import re

def patient_identifier(i):
    return i.startswith(('uhid','jjh','snj','dhh')) and 'ipd' not in i

def encounter_identifier(i):
    return i.startswith(('adm','ipd','ip26','dhhipd')) or (
        i.startswith('ip') and not i.startswith('ipd') and i[2:].isdigit())

class InternalLinks:
    def __init__(self, evidence_sets, registrations=()):
        # A visit identifier is usable only when the source explicitly pairs
        # it with exactly one patient identifier. Conflicts are never merged.
        self.owners=defaultdict(set)
        self.canonical={}
        # Reconcile authoritative duplicate registrations only using an exact
        # full government ID explicitly stored in a registration record.
        # The comparison key is keyed; it is never exported.
        keys_by_internal=defaultdict(set)
        for record in registrations:
            ids={i for i in evidence(record) if patient_identifier(i)}
            if len(ids)!=1: continue
            keys=set()
            def scan(v,k=''):
                if isinstance(v,dict):
                    for a,b in v.items(): scan(b,a)
                elif isinstance(v,list):
                    for x in v: scan(x,k)
                elif isinstance(v,(str,int)):
                    if norm(k) in ('aadhaar','aadhar','aadhaarno','aadharno','aadhaarnumber','aadharnumber'):
                        raw=str(v)
                        if re.fullmatch(r'[0-9 -]+',raw):
                            digits=re.sub(r'[^0-9]','',raw)
                            if len(digits)==12:
                                keys.add(token('INTERNAL',digits,32))
            scan(record)
            if keys: keys_by_internal[next(iter(ids))].update(keys)
        by_key=defaultdict(set)
        for internal,keys in keys_by_internal.items():
            if len(keys)==1: by_key[next(iter(keys))].add(internal)
        for group in by_key.values():
            if len(group)>1:
                canonical=min(group)
                for internal in group: self.canonical[internal]=canonical
        for ids in evidence_sets:
            primary={i for i in ids if patient_identifier(i)}
            if len(primary)==1:
                for encounter in ids:
                    if encounter_identifier(encounter):
                        self.owners[encounter].update(primary)
            elif len(primary)>1:
                for encounter in ids:
                    if encounter_identifier(encounter):
                        self.owners[encounter].update(primary)

    def resolve(self,ids):
        primary={i for i in ids if patient_identifier(i)}
        primary={self.canonical.get(i,i) for i in primary}
        if len(primary)>1:
            return None
        candidates=set(primary)
        for encounter in ids:
            if encounter_identifier(encounter):
                candidates.update(self.canonical.get(i,i) for i in self.owners.get(encounter,()))
        if len(candidates)>1:
            return None
        if len(candidates)==1:
            return pseudonym(next(iter(candidates)))
        # Retain prior single internal ID behavior, but never link anonymous
        # names or external IDs.
        if len(ids)==1:
            return pseudonym(next(iter(ids)))
        return None
