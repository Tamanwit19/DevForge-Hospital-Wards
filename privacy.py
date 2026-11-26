"""Offline, conservative de-identification of synthetic hospital exports."""
import re, unicodedata
from datetime import datetime, timedelta
from crypto import pseudonym, date_shift_days

ID = re.compile(r'(?i)\b(?:UHID[-/]\d+|JJH-\d+|SNJ[-/]\d{2}[-/]\d+|DHH(?:-IPD-\d+|\d{4}-\d+)|ADM\d+|IP[-/]\d{2}[-/]\d+|IPD-\d{4}-\d+|OPD/\d+/\d+/\d+|PMJAY-[A-Z]+-\d+|POL/\d+/\d+|[A-Z]{5}\d{4}[A-Z])\b')
PHONE = re.compile(r'(?<!\w)(?:\+91[ -]?)?\d{5}[ -]?\d{5}(?!\w)')
OTHER = re.compile(r'(?i)(?<!\w)(?:\d{4}[ -]?\d{4}[ -]?\d{4}|\d{2}-\d{4}-\d{4}-\d{4}|XXXX[ -]?XXXX[ -]?\d{4}|[\w.+-]+@[\w.-]+)(?!\w)')
DATE = re.compile(r'\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}[-/]\d{1,2}[-/]\d{4})\b')
LABEL = re.compile(r'(?im)(\b(?:patient\s*name|name|relative name|guardian|attendant|address|village|gram|mobile|mob\.?|phone|aadhaar|aadhar|abha|dob|s/o|d/o|w/o)\s*[:.]?\s+|(?:नाम|ग्राम|पता|मोबाइल|जन्म तिथि)\s*:\s*)([^\n\r]*?)(?=\s{2,}|[,;]|\r?$|\s+(?:Age|Sex|Reg No|UHID|Mob|BP|आयु)\s*[:/])')
AGE = re.compile(r'(?i)(\b(?:age(?:/sex)?|umar)\s*:\s*|आयु\s*:\s*)(\d{1,3})')
def norm(s):
    return ''.join(c for c in unicodedata.normalize('NFKC',str(s)).casefold() if c.isalnum() or unicodedata.category(c).startswith('M'))
def kind(key):
    k=norm(key)
    if k in {'name','naam','patientname','firstname','lastname','first','last','local','given','family','नाम','patient','patientfullname','fullname','patientlegalname','patientdisplayname','patientnm','नाम','रोगीकानाम','मरीजकानाम','रोगीनाम'}: return 'name'
    if any(x in k for x in ('guardian','relativename','pitapatikanaam','attendant','fathername','husbandname','mothername')): return 'relative'
    if any(x in k for x in ('phone','mobile','aadhaar','aadhar','abha','email','pan','insurance','pmjay','policyno','contactnumber','contactno','telephone','canary','मोबाइल','दूरभाष','फोन','ईमेल')): return 'private'
    if k in {'uhid','mrn','patientid','patientref','hospitaluhid','regno','ipdno','admissionid','visitid','billno','registrationid','hospitalid','recordid','medicalrecordnumber','patientnumber','registrationnumber','hospitalrecordnumber','mrnumber'}: return 'id'
    if k.startswith('dob') or k in {'birthdate','janmtithi','dateofbirth'}: return 'dob'
    if k in {'age','umar','patientage','ageyears','आयु','उम्र','आयु'}: return 'age'
    if k in {'pin','pincode','zip','postalcode'}: return 'pin'
    if k in {'addressnote','address','pata','street','line','village','villagemohalla','gaon','city','tehsil','house','locality','landmark','residentialaddress','homeaddress','addressline','addressline1','addressline2','patientaddress','पता','sourcepath','exportedby','filename','attachment','data'}: return 'location'
    return ''
def band(n,width=5,top=90):
    return f'{top}+' if n>=top else f'{n//width*width}-{min(top-1,n//width*width+width-1)}'
def shift(m,days,monthfirst=False):
    s=m.group()
    for fmt in (['%Y-%m-%d','%m/%d/%Y','%d/%m/%Y','%d-%m-%Y'] if monthfirst else ['%Y-%m-%d','%d/%m/%Y','%m/%d/%Y','%d-%m-%Y']):
        try: return (datetime.strptime(s,fmt)+timedelta(days=days)).strftime(fmt)
        except ValueError: pass
    return '[DATE]'
def evidence(obj):
    """Only explicit hospital identifiers; never infer identity from public registries."""
    ids=set()
    def scan(x,k=''):
        if isinstance(x,dict):
            for a,b in x.items(): scan(b,a)
        elif isinstance(x,list):
            for i in x: scan(i,k)
        elif isinstance(x,(str,int)):
            s=str(x)
            ids.update(norm(v.group()) for v in ID.finditer(s) if not re.match(r'(?i)^(OPD|POL|PMJAY)',v.group()))
            if kind(k)=='id' and k.lower() not in ('visit_id','bill_no') and len(s)>3: ids.add(norm(s))
    scan(obj)
    return ids
class Sanitizer:
    def __init__(self, aliases, policy):
        self.aliases=aliases
        self.policy=policy
        self.detected=0
        self.generalized=0
    def redact(self,replacement='[REDACTED]'):
        self.detected+=1
        return replacement
    def text(self,s,patient=None,days=0,monthfirst=False):
        def label(m):
            pre,val=m.groups()
            if not val.strip(): return m.group()
            return pre+self.redact(patient if patient and norm(pre) in ('name','patientname','नाम') else '[REDACTED]')
        # Context-specific spans in clinical notes, messages and visitor logs.
        patterns = [
            r"(?im)(^\s*(?:discharge note|opd note for)\s+)([^,.;\r\n]+)(?=[,.;])",
            r"(?i)(sample received from\s+)([^'’\r\n]+)(?=['’]s attendant)",
            r"(?im)(^\s*\[\d{1,2}/\d{1,2}/\d{2,4},[^\]\r\n]+\]\s*)([^:\r\n]+)(?=:)",
            r"(?im)(^\s*\d{1,2}:\d{2}\s*-\s*)([^\r\n]+?)(?=\s+-\s*(?:K/C/O|C/O|H/O)|\s*\(attendant)",
            r"(?i)(\bcalled by\s+)([^\d,;\r\n]+)",
            r"(?im)(^\s*)([^\r\n:]+?)(?=\s+ka\s+BP\b)",
        ]
        for pattern in patterns:
            s=re.sub(pattern,lambda m:m[1]+self.redact(patient or '[NAME]')+' ',s)
        s=re.sub(r'(?im)(\baddress\s*[:.]?\s+)[^\r\n]+',lambda m:m[1]+self.redact(),s)
        s=LABEL.sub(label,s)
        s=ID.sub(lambda m:self.redact(patient or '[ID]'),s)
        s=OTHER.sub(lambda m:self.redact(),s)
        s=PHONE.sub(lambda m:self.redact(),s)
        def age(m):
            self.generalized+=1
            return m[1]+band(int(m[2]),self.policy.get('age_band_width',5),self.policy.get('age_top_code',90))
        s=AGE.sub(age,s)
        def shift_date(m):
            self.generalized+=1
            return shift(m,days,monthfirst)
        s=DATE.sub(shift_date,s)
        # Remove names learned from explicitly labelled fields; protect clinician mentions.
        for pattern in self.aliases:
            s=pattern.sub(lambda m:m.group() if re.search(r'(?i)Dr\.?\s*$',s[max(0,m.start()-5):m.start()]) else self.redact(patient or '[NAME]'),s)
        s=re.sub(r'(?i)(?<!\w)[^\W\d_]+(?=\s+(?:sahab|bhai|behenji|amma|didi|ji|babu)\b)',lambda m:self.redact(patient or '[NAME]'),s)
        s=re.sub(r'(?im)(\b(?:address|ग्राम|पता)\s*:\s*)[^\r\n]+',lambda m:m[1]+self.redact(),s)
        return s
    def value(self,x,k='',patient=None,days=0,monthfirst=False,path=()):
        typ=kind(k)
        if isinstance(x,dict):
            if norm(k)=='byname':
                return {f'entry_{i}':self.value(v,'patientref',patient,days,monthfirst,path+(k,)) for i,v in enumerate(x.values())}
            if x.get('resourceType') in ('Practitioner','Organization'):
                path=path+(x['resourceType'],)
            if x.get('resourceType')=='Bundle':
                path=path+('bundle',)
            if x.get('resourceType')=='Patient':
                path=path+('patient',)
            out={}
            for a,b in x.items():
                key=self.text(a,days=0)
                if key in out:
                    key=f'{key}_{len(out)}'
                if a=='display' and norm(k) in ('subject','patient','individual'):
                    out[key]=self.redact(patient or '[NAME]') if isinstance(b,str) else b
                elif a=='valueString' and any(word in str(x.get('url','')).casefold() for word in ('mother','father','guardian','relative','name')):
                    out[key]=self.redact()
                else:
                    out[key]=self.value(b,a,patient,days,monthfirst,path+(k,))
            return out
        if isinstance(x,list):
            return [self.value(v,k,patient,days,monthfirst,path) for v in x]
        if x is None or isinstance(x,bool) or x=='': return x
        # FHIR structural UUIDs are transformed atomically by the bundle guard;
        # generic numeric regexes must not partially corrupt these references.
        if isinstance(x,str) and 'bundle' in path and norm(k) in ('id','fullurl','reference','value'):
            if re.fullmatch(r'(?i)(?:(?:urn:uuid:|[A-Za-z]+/))?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',x):
                return x
        if norm(k)=='text' and 'name' in tuple(map(norm,path)) and isinstance(x,str):
            return self.redact(patient or '[NAME]')
        if norm(k)=='div' and 'patient' in tuple(map(norm,path)) and isinstance(x,str):
            # Keep the XHTML wrapper and generalize demographic narrative.
            x=re.sub(r'(?i)(<div\b[^>]*>)[^<,]+(?=,)',lambda m:m[1]+self.redact(patient or '[NAME]'),x,count=1)
            x=re.sub(r'(?i)\b(\d{1,3})\s*(yrs?|years?)\b',lambda m:band(int(m[1]),self.policy.get('age_band_width',5),self.policy.get('age_top_code',90))+' '+m[2],x)
        if typ=='name' and any(norm(i) in ('facility','panels','results','organization','practitioner') for i in path): typ=''
        if typ in ('name','id','relative','private','location','dob'):
            if isinstance(x,(int,float)): return int(self.redact('0'))
            return self.redact((patient or '[REDACTED]') if typ in ('name','id') else '[REDACTED]')
        if typ=='age':
            m=re.match(r'\d+',str(x))
            if m:
                n=int(m.group()); self.generalized+=1; return min(self.policy.get('age_top_code',90),n//self.policy.get('age_band_width',5)*self.policy.get('age_band_width',5)) if isinstance(x,int) else band(n,self.policy.get('age_band_width',5),self.policy.get('age_top_code',90))
        if typ=='pin':
            self.generalized+=1
            return self.redact(str(x)[:3]+'XXX') if isinstance(x,str) else 0
        if typ=='' and norm(k) in ('district','jila') and self.policy.get('location_level')=='suppressed':
            self.generalized+=1
            return self.redact()
        if isinstance(x,str): return self.text(x,patient,days,monthfirst)
        return x
def alias_patterns(items):
    names=set()
    def visit(x,k=''):
        if isinstance(x,dict):
            for a,b in x.items(): visit(b,a)
        elif isinstance(x,list):
            for v in x: visit(v,k)
        elif isinstance(x,str):
            if kind(k) in ('name','relative') and 3<=len(x)<=80: names.add(x.strip())
            for m in LABEL.finditer(x):
                if norm(m[1]) in ('name','patientname','नाम','relative name','guardian','so','wo','do'): names.add(m[2].strip())
    for x in items: visit(x)
    return [re.compile(r'(?<!\w)'+re.escape(n)+r'(?!\w)',re.I) for n in sorted(names,key=lambda n:(-len(n),n)) if len(n)>2 and not re.search(r'\d|\[|\n',n)]
