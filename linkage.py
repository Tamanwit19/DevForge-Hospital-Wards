"""Conservative identity resolution using strong IDs and corroborated name clues."""
from collections import defaultdict
from datetime import datetime
from difflib import SequenceMatcher
from itertools import combinations
import re

from crypto import pseudonym, token
from identity_normalization import canonical_tokens
from privacy import evidence, kind, norm, LABEL


_RELATIVE_PAIR = re.compile(
    r'(?i)(?P<patient>[\w\u0900-\u097f.\-]+(?:[ \t,]+[\w\u0900-\u097f.\-]+){0,2})[ \t]*,?[ \t]+'
    r'(?P<relation>s/o|d/o|w/o|पुत्र|पुत्री|पत्नी)[ \t]+'
    r'(?P<relative>[\w\u0900-\u097f.\-]+(?:[ \t]+[\w\u0900-\u097f.\-]+){0,2})'
)
_TEXT_AGE = re.compile(
    r'(?i)(?:\bage(?:/sex)?|umar|आयु|उम्र)\s*[:=]?\s*([0-9०-९]{1,3})'
    r'|(?<!\d)([0-9०-९]{1,3})\s*(?:y(?:rs?)?|years?)\s*/\s*[mf]\b'
    r'|(?<!\d)([0-9०-९]{1,3})\s*/\s*[mf]\b'
)
_TEXT_RECORD_DATE = re.compile(
    r'(?i)(?:\b(?:date|date of visit|visit date|encounter date|discharge date)\b|तारीख|दिनांक)'
    r'\s*[:=]\s*([0-9०-९]{1,4}[-/.][0-9०-९]{1,2}[-/.][0-9०-९]{1,4})'
)
_RECORD_DATE_KEYS = {
    'date', 'visitdate', 'encounterdate', 'dischargedate', 'servicedate',
    'authoredon', 'issuedate', 'dateissued'
}
_TEXT_PATIENT_NAMES = (
    re.compile(
        r'(?i)\b(?:report|prescription|note)\s+(?:of|for)\s+'
        r'(?P<name>[\w\u0900-\u097f.\-]+(?:\s+[\w\u0900-\u097f.\-]+){0,2})'
        r'(?=\s+[0-9०-९]{1,3}\s*(?:y\b|yrs?\b|years?\b)|[,;.\r\n]|$)'
    ),
    re.compile(
        r'(?im)^\s*\d{1,2}:\d{2}\s*-\s*'
        r'(?P<name>[^-\r\n]+?)(?=\s+-\s*(?:K/C/O|C/O|H/O)\b)'
    ),
    re.compile(
        r'(?im)(?:^|[-:]\s*)(?P<name>[\w\u0900-\u097f.\-]+'
        r'(?:\s+[\w\u0900-\u097f.\-]+){0,2})\s+'
        r'(?:sahab|sahib|ji|didi|babu|bhai|behenji|amma)\s+(?:ka|ki|ke)\b'
    ),
)


def patient_identifier(identifier):
    if encounter_identifier(identifier):
        return False
    if identifier.startswith(('contact:', 'contact-text:', 'opd', 'pol', 'pmjay')):
        return False
    return bool(re.fullmatch(r'[a-z]{2,}[/-]?[a-z0-9/-]{3,}', identifier))


def encounter_identifier(identifier):
    return identifier.startswith(('adm', 'ipd', 'ip26', 'dhhipd')) or (
        identifier.startswith('ip') and not identifier.startswith('ipd') and identifier[2:].isdigit())


def _date_values(value):
    if not isinstance(value, str):
        return set()
    value = value.strip().translate(str.maketrans('०१२३४५६७८९', '0123456789'))
    for fmt in ('%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%d-%m-%Y', '%d.%m.%Y'):
        try:
            return {datetime.strptime(value[:10], fmt).date().isoformat()}
        except ValueError:
            continue
    return set()


def _age_on(dob, event_date):
    birth=datetime.strptime(dob,'%Y-%m-%d').date()
    event=datetime.strptime(event_date,'%Y-%m-%d').date()
    return event.year-birth.year-((event.month,event.day)<(birth.month,birth.day))


def _village_key(key):
    return norm(key) in {
        'village', 'gaon', 'gram', 'villagemohalla', 'villageorward',
        'गांव', 'गाँव', 'ग्राम'
    }


def identity_features(record):
    names = []
    relatives = []
    dob_values = set()
    ages = set()
    record_dates = set()
    villages = set()
    def visit(value, key='', path=()):
        if isinstance(value, dict):
            resource_type = value.get('resourceType')
            next_path = path + ((resource_type,) if resource_type else ())
            for child_key, child in value.items():
                visit(child, child_key, next_path)
            return
        if isinstance(value, list):
            for child in value:
                visit(child, key, path)
            return
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return

        key_kind = kind(key)
        if key_kind == 'name' and not any(norm(part) in ('practitioner', 'organization', 'facility') for part in path):
            names.append((key, str(value)))
        elif key_kind == 'relative':
            relatives.append(str(value))
        if key_kind == 'dob':
            dob_values.update(_date_values(str(value)))
        if norm(key) in _RECORD_DATE_KEYS:
            record_dates.update(_date_values(str(value)))
        if key_kind == 'age':
            match = re.search(r'[0-9०-९]{1,3}', str(value))
            if match and 0 <= int(match.group()) <= 120:
                ages.add(int(match.group().translate(str.maketrans('०१२३४५६७८९', '0123456789'))))
        if _village_key(key):
            village = canonical_tokens(value)
            if village:
                villages.add(village)

        if isinstance(value, str):
            for pattern in _TEXT_PATIENT_NAMES:
                names.extend(('patient_name', match.group('name')) for match in pattern.finditer(value))
            for match in _TEXT_AGE.finditer(value):
                surface = next((group for group in match.groups() if group), None)
                if surface:
                    age = int(surface.translate(str.maketrans('०१२३४५६७८९', '0123456789')))
                    if 0 <= age <= 120:
                        ages.add(age)
            for match in _TEXT_RECORD_DATE.finditer(value):
                record_dates.update(_date_values(match.group(1)))
            for match in _RELATIVE_PAIR.finditer(value):
                names.append(('patient_name', match.group('patient')))
                relatives.append(match.group('relative'))
            for match in LABEL.finditer(value):
                prefix, surface = match.groups()
                prefix_key = norm(prefix)
                if prefix_key in ('so', 'wo', 'do', 's/o', 'w/o', 'd/o'):
                    relatives.append(surface)
                elif kind(prefix) == 'relative':
                    relatives.append(surface)
                elif kind(prefix) == 'name':
                    names.append((prefix, surface))
                elif _village_key(prefix):
                    village = canonical_tokens(surface)
                    if village:
                        villages.add(village)
                elif kind(prefix) == 'dob':
                    dob_values.update(_date_values(surface.translate(str.maketrans('०१२३४५६७८९', '0123456789'))))

    visit(record)

    name_values = [canonical_tokens(value) for _, value in names]
    name_values = [value for value in name_values if value]
    name_signatures = set(name_values)

    split_fields = [value for key, value in names if norm(key) in {
        'firstname', 'givenname', 'given', 'lastname', 'familyname', 'family', 'surname'
    }]
    if len(split_fields) > 1:
        combined = canonical_tokens(' '.join(split_fields))
        if combined:
            name_signatures.add(combined)

    relative_signatures = {
        signature for signature in (canonical_tokens(value) for value in relatives)
        if signature
    }
    return {
        'names': name_signatures,
        'relatives': relative_signatures,
        'dob': dob_values,
        'ages': ages,
        'dates': record_dates,
        'villages': villages,
    }


def identity_clues(features):
    clues = set()
    for name in features['names']:
        if not name or (len(name) == 1 and name[0] in {'devi', 'kumar', 'kumari', 'singh', 'muhammad', 'ji'}):
            continue
        for relative in features['relatives']:
            clues.add(('name-relative', name, relative))
        for dob in features['dob']:
            clues.add(('name-dob', name, dob))
        for village in features['villages']:
            for age in features['ages']:
                for nearby_age in range(max(0, age - 1), min(120, age + 1) + 1):
                    clues.add(('name-village-age', name, village, nearby_age))
    return clues


def _phonetic_token(value):
    groups={
        'bfpv':'1','cgjkqsxz':'2','dt':'3','l':'4','mn':'5','r':'6'
    }
    if not value:
        return ''
    codes=[]
    for char in value[1:]:
        code=next((number for letters,number in groups.items() if char in letters),'')
        if code and (not codes or code!=codes[-1]):
            codes.append(code)
    return (value[0]+''.join(codes)+'000')[:4]


def _phonetic_name(name):
    return tuple(_phonetic_token(word) for word in name)


def _name_similarity(target, known):
    if set(target).issubset(known):
        return 0.94
    score = SequenceMatcher(None, ' '.join(target), ' '.join(known)).ratio()
    if _phonetic_name(target) == _phonetic_name(known):
        score = max(score, 0.94)
    return score


class InternalLinks:
    def __init__(self, evidence_sets, registrations=()):
        evidence_sets = list(evidence_sets)
        registrations = list(registrations)
        self.owners = defaultdict(set)
        self.contact_owners = defaultdict(set)
        self.identity_owners = defaultdict(set)
        self.identity_blocks = defaultdict(list)
        self.owner_features = defaultdict(
            lambda: {'names': set(), 'relatives': set(), 'dob': set(), 'ages': set(), 'dates': set(), 'villages': set()}
        )
        self.canonical = {}

        keys_by_internal = defaultdict(set)
        for record in registrations:
            ids = {i for i in evidence(record) if patient_identifier(i)}
            if len(ids) != 1:
                continue
            keys = set()

            def scan(value, key=''):
                if isinstance(value, dict):
                    for child_key, child in value.items():
                        scan(child, child_key)
                elif isinstance(value, list):
                    for child in value:
                        scan(child, key)
                elif isinstance(value, (str, int)) and norm(key) in (
                    'aadhaar', 'aadhar', 'aadhaarno', 'aadharno',
                    'aadhaarnumber', 'aadharnumber'
                ):
                    digits = re.sub(r'\D', '', str(value))
                    if len(digits) == 12:
                        keys.add(token('INTERNAL', digits, 32))

            scan(record)
            if keys:
                keys_by_internal[next(iter(ids))].update(keys)

        by_key = defaultdict(set)
        for internal, keys in keys_by_internal.items():
            if len(keys) == 1:
                by_key[next(iter(keys))].add(internal)
        for group in by_key.values():
            if len(group) > 1:
                canonical = min(group)
                for internal in group:
                    self.canonical[internal] = canonical

        for record in registrations:
            ids = {self.canonical.get(i, i) for i in evidence(record) if patient_identifier(i)}
            if len(ids) == 1:
                owner = next(iter(ids))
                features=identity_features(record)
                profile=self.owner_features[owner]
                for feature in profile:
                    profile[feature].update(features[feature])
                clues=identity_clues(features)
                for clue in clues:
                    self.identity_owners[clue].add(owner)
                    block=None
                    if clue[0]=='name-relative':
                        block=('relative',clue[2])
                    elif clue[0]=='name-dob':
                        block=('dob',clue[2])
                    elif clue[0]=='name-village-age':
                        block=('village-age',clue[2],clue[3])
                    if block:
                        self.identity_blocks[block].append((clue[1],owner))
                        if clue[0]=='name-village-age':
                            self.identity_blocks[('village-age-candidates',clue[3])].append(
                                (clue[2],clue[1],owner)
                            )

        parent={owner:owner for owner in self.owner_features}

        def find(owner):
            while parent[owner]!=owner:
                parent[owner]=parent[parent[owner]]
                owner=parent[owner]
            return owner

        owners=list(parent)
        owners_by_dob=defaultdict(set)
        for owner in owners:
            for dob in self.owner_features[owner]['dob']:
                owners_by_dob[dob].add(owner)
        for matching_dob in owners_by_dob.values():
            for first,second in combinations(sorted(matching_dob),2):
                first_profile=self.owner_features[first]
                second_profile=self.owner_features[second]
                name_score=max(
                    (_name_similarity(a,b) for a in first_profile['names'] for b in second_profile['names']),
                    default=0.0
                )
                relative_score=max(
                    (_name_similarity(a,b) for a in first_profile['relatives'] for b in second_profile['relatives']),
                    default=0.0
                )
                if name_score>=0.92 and relative_score>=0.92:
                    a,b=find(first),find(second)
                    parent[max(a,b)]=min(a,b)

        def canonical_owner(owner):
            root=find(owner) if owner in parent else self.canonical.get(owner,owner)
            self.canonical[owner]=root
            return root

        for identifier,owner in list(self.canonical.items()):
            self.canonical[identifier]=canonical_owner(owner)
        for owner in owners:
            canonical_owner(owner)

        merged_features=defaultdict(
            lambda:{'names':set(),'relatives':set(),'dob':set(),'ages':set(),'dates':set(),'villages':set()}
        )
        for owner,profile in self.owner_features.items():
            target=merged_features[canonical_owner(owner)]
            for feature in target:
                target[feature].update(profile[feature])
        self.owner_features=merged_features

        merged_identity_owners=defaultdict(set)
        for clue,clue_owners in self.identity_owners.items():
            merged_identity_owners[clue].update(canonical_owner(owner) for owner in clue_owners)
        self.identity_owners=merged_identity_owners

        merged_identity_blocks=defaultdict(list)
        for block,entries in self.identity_blocks.items():
            for entry in entries:
                merged_identity_blocks[block].append((*entry[:-1],canonical_owner(entry[-1])))
        self.identity_blocks=merged_identity_blocks

        for ids in evidence_sets:
            primary = {self.canonical.get(i, i) for i in ids if patient_identifier(i)}
            contacts = {i for i in ids if i.startswith('contact:')}
            if len(primary) == 1:
                owner = next(iter(primary))
                for encounter in ids:
                    if encounter_identifier(encounter):
                        self.owners[encounter].add(owner)
                for contact in contacts:
                    self.contact_owners[contact].add(owner)
            elif len(primary) > 1:
                for encounter in ids:
                    if encounter_identifier(encounter):
                        self.owners[encounter].update(primary)

    def resolve(self, ids, record=None):
        primary = {self.canonical.get(i, i) for i in ids if patient_identifier(i)}
        if len(primary) > 1:
            return None
        candidates = set(primary)
        for encounter in ids:
            if encounter_identifier(encounter):
                candidates.update(self.owners.get(encounter, ()))
        for contact in ids:
            if contact.startswith('contact:'):
                owners = self.contact_owners.get(contact, ())
                if len(owners) == 1:
                    candidates.update(owners)
        if len(candidates)>1:
            return None
        if not candidates and record is not None:
            features=identity_features(record)
            for contact in ids:
                if not contact.startswith('contact-text:phone:'):
                    continue
                owner_key=contact.replace('contact-text:', 'contact:', 1)
                owners=self.contact_owners.get(owner_key, ())
                if not owners or not features['names']:
                    continue
                matching_owners=set()
                for owner in owners:
                    profile=self.owner_features.get(owner)
                    if not profile:
                        continue
                    if features['ages'] and profile['ages'] and not any(
                        abs(actual-age)<=2 for actual in features['ages'] for age in profile['ages']
                    ):
                        continue
                    name_score=max(
                        (_name_similarity(name,known) for name in features['names'] for known in profile['names']),
                        default=0.0
                    )
                    if name_score>=0.92:
                        matching_owners.add(owner)
                if len(matching_owners)==1:
                    candidates.update(matching_owners)
            if not candidates:
                date_scores=defaultdict(float)
                if features['dates'] and features['ages'] and features['names'] and features['villages']:
                    for owner,profile in self.owner_features.items():
                        name_score=max(
                            (_name_similarity(name,known) for name in features['names'] for known in profile['names']),
                            default=0.0
                        )
                        village_score=max(
                            (
                                max(
                                    SequenceMatcher(None,' '.join(village),' '.join(known)).ratio(),
                                    0.94 if _phonetic_name(village)==_phonetic_name(known) else 0.0
                                )
                                for village in features['villages'] for known in profile['villages']
                            ),
                            default=0.0
                        )
                        if name_score<0.92 or village_score<0.92:
                            continue
                        age_matches=any(
                            abs(age-_age_on(dob,event_date))<=1
                            for age in features['ages']
                            for dob in profile['dob']
                            for event_date in features['dates']
                        )
                        if age_matches:
                            date_scores[owner]=min(name_score,village_score)
                ranked_dates=sorted(date_scores.items(),key=lambda item:(-item[1],item[0]))
                if ranked_dates and ranked_dates[0][1]>=0.92 and (
                    len(ranked_dates)==1 or ranked_dates[0][1]-ranked_dates[1][1]>=0.08
                ):
                    candidates.add(ranked_dates[0][0])
            if not candidates:
                for clue in identity_clues(features):
                    owners = self.identity_owners.get(clue, ())
                    if len(owners) == 1:
                        candidates.update(owners)
                    elif not owners:
                        scores=defaultdict(float)
                        if clue[0]=='name-relative':
                            for owner,profile in self.owner_features.items():
                                name_score=max(
                                    (_name_similarity(clue[1],name) for name in profile['names']),
                                    default=0.0
                                )
                                relative_score=max(
                                    (_name_similarity(clue[2],relative) for relative in profile['relatives']),
                                    default=0.0
                                )
                                if name_score>=0.92 and relative_score>=0.92:
                                    scores[owner]=min(name_score,relative_score)
                        elif clue[0]=='name-dob':
                            for owner,profile in self.owner_features.items():
                                if clue[2] in profile['dob']:
                                    name_score=max(
                                        (_name_similarity(clue[1],name) for name in profile['names']),
                                        default=0.0
                                    )
                                    if name_score>=0.92:
                                        scores[owner]=name_score
                        elif clue[0]=='name-village-age':
                            block_candidates=self.identity_blocks.get(('village-age-candidates',clue[3]),())
                            for known_village,known_name,owner in block_candidates:
                                village_score=SequenceMatcher(
                                    None,' '.join(clue[2]),' '.join(known_village)
                                ).ratio()
                                if _phonetic_name(clue[2])==_phonetic_name(known_village):
                                    village_score=max(village_score,0.94)
                                name_score=_name_similarity(clue[1],known_name)
                                if village_score>=0.92 and name_score>=0.92:
                                    scores[owner]=max(scores[owner],min(village_score,name_score))
                        ranked=sorted(scores.items(),key=lambda item:(-item[1],item[0]))
                        if ranked and ranked[0][1]>=0.92 and (
                            len(ranked)==1 or ranked[0][1]-ranked[1][1]>=0.08
                        ):
                            candidates.add(ranked[0][0])
        if len(candidates) > 1:
            return None
        if len(candidates) == 1:
            return pseudonym(next(iter(candidates)))
        if len(ids) == 1:
            only = next(iter(ids))
            if not only.startswith(('contact:', 'contact-text:')):
                return pseudonym(only)
        return None
