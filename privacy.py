"""Offline, conservative de-identification of synthetic hospital exports."""
import re, unicodedata
from datetime import datetime, timedelta
from crypto import pseudonym, date_shift_days, token
from identity_normalization import canonical_tokens

ID = re.compile(
    r'(?i)\b(?:'
    r'UHID[-/]\d+|JJH-\d+|SNJ[-/]\d{2}[-/]\d+|DHH(?:-IPD-\d+|\d{4}-\d+)'
    r'|ADM\d+|IP[-/]\d{2}[-/]\d+|IPD-\d{4}-\d+|OPD/\d+/\d+/\d+'
    r'|PMJAY-[A-Z]+-\d+|POL/\d+/\d+|[A-Z]{5}\d{4}[A-Z]'
    r'|[A-Z]{2,}[/-]?[0-9][A-Z0-9/-]{4,}'
    r')\b'
)
PHONE = re.compile(
    r'(?<!\w)(?:'
    r'\+91[\s-]?[6-9\u0966-\u0969]\d{9}'
    r'|0(?:[1-9]\d{1,2})[\s-]?\d{6,8}'
    r'|[6-9\u0966-\u0969]\d{9}'
    r'|\d{5}[\s-]?\d{5}'
    r')(?!\w)'
)
PLAIN_ID = re.compile(r'(?<!\d)[0-9\u0966-\u096f]{6,7}(?!\d)')
OTHER = re.compile(r'(?i)(?<!\w)(?:\d{4}[ -]?\d{4}[ -]?\d{4}|\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{2}|\d{2}-\d{4}-\d{4}-\d{4}|XXXX[ -]?XXXX[ -]?\d{4}|[\w.+-]+@[\w.-]+)(?!\w)')
DATE = re.compile(
    r'(?i)\b(?:'
    r'\d{4}-\d{2}-\d{2}'
    r'|\d{1,2}[-/]\d{1,2}[-/]\d{4}'
    r'|\d{1,2}(?:st|nd|rd|th)?\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|'
    r'may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)'
    r'\s+\d{4}'
    r'|(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|'
    r'aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)'
    r'\s+\d{1,2}(?:st|nd|rd|th)?(?:,)?\s+\d{4}'
    r'|(?:०?\d{1,2}|[\d]{1,2})\s+(?:जनवरी|फ़रवरी|फरवरी|मार्च|अप्रैल|मई|जून|जुलाई|'
    r'अगस्त|सितम्बर|सितंबर|अक्टूबर|नवम्बर|नवंबर|दिसम्बर|दिसंबर)\s+\d{4}'
    r')\b'
)
LABEL = re.compile(r'(?im)(\b(?:patient\s*name|name|relative name|guardian|attendant|address|village|gram|district|jila|tehsil|mobile|mob\.?|phone|telephone|mrn|medical\s*record(?:\s*number)?|patient\s*id|hospital\s*id|reg(?:istration)?(?:\s*no\.?)?|ipd(?:\s*no\.?)?|aadhaar|aadhar|abha|dob|s/o|d/o|w/o)\s*[:.]?\s+|(?:नाम|ग्राम|पता|जिला|तहसील|मोबाइल|जन्म तिथि|पंजीकरण संख्या)\s*:\s*)([^\n\r]*?)(?=\s{2,}|[,;]|\r?$|\s+(?:Age|Sex|Reg No|UHID|Mob|BP|आयु)\s*[:/])')
AGE = re.compile(r'(?i)(\b(?:age(?:/sex)?|umar)\s*:\s*|आयु\s*:\s*)(\d{1,3})')
RELATIVE_PAIR = re.compile(
    r'(?i)(?P<patient>[\w\u0900-\u097f.\-]+(?:[ \t,]+[\w\u0900-\u097f.\-]+){0,2})[ \t]*,?[ \t]+'
    r'(?P<relation>s/o|d/o|w/o|पुत्र|पुत्री|पत्नी)[ \t]+'
    r'(?P<relative>[\w\u0900-\u097f.\-]+(?:[ \t]+[\w\u0900-\u097f.\-]+){0,2})'
)

class AliasPatterns(list):
    def __init__(self,names,full_names):
        names=list(names)
        full_names=list(full_names)
        super().__init__(
            re.compile(r'(?<!\w)'+re.escape(name)+r'(?!\w)',re.I)
            for name in sorted(names,key=lambda item:(-len(item),item))
            if len(name)>2 and not re.search(r'\d|\[|\n',name)
        )
        self.text_patterns=[
            re.compile(r'(?<!\w)'+re.escape(name)+r'(?!\w)',re.I)
            for name in sorted(set(full_names),key=lambda item:(-len(item),item))
            if len(name)>2 and not re.search(r'\d|\[|\n',name)
        ]
        signatures={canonical_tokens(name) for name in full_names}
        self.identity_signatures={value for value in signatures if len(value)>1}
        self.single_signatures={
            value for value in signatures if len(value)==1 and value[0] not in
            {'devi','kumar','kumari','singh','muhammad','ji'}
        }
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
    if k in {'district','districtname','jila','जिला'}: return 'district'
    if k in {'addressnote','address','pata','street','line','village','villagemohalla','gaon','city','tehsil','house','locality','landmark','residentialaddress','homeaddress','addressline','addressline1','addressline2','patientaddress','पता','sourcepath','exportedby','filename','attachment','data'}: return 'location'
    return ''
def band(n,width=5,top=90):
    return f'{top}+' if n>=top else f'{n//width*width}-{min(top-1,n//width*width+width-1)}'
def shift(m,days,monthfirst=False):
    s=m.group()
    formats=[
        '%Y-%m-%d','%d %B %Y','%d %b %Y','%B %d, %Y','%b %d, %Y',
        '%d %B %Y','%d %b %Y','%d/%m/%Y','%m/%d/%Y','%d-%m-%Y','%d.%m.%Y'
    ]
    if monthfirst:
        formats=['%Y-%m-%d','%m/%d/%Y','%d/%m/%Y','%d-%m-%Y','%d.%m.%Y',
                  '%d %B %Y','%d %b %Y','%B %d, %Y','%b %d, %Y']
    for fmt in formats:
        try:
            shifted=(datetime.strptime(re.sub(r'(?i)(\d{1,2})(st|nd|rd|th)\b',r'\1',s),fmt)+timedelta(days=days))
            if fmt.startswith('%d '):
                day=shifted.day
                suffix='th' if 11<=day<=13 else {1:'st',2:'nd',3:'rd'}.get(day%10,'th')
                if re.search(r'(?i)\d+(st|nd|rd|th)',s):
                    return shifted.strftime('%d').lstrip('0')+suffix+' '+shifted.strftime('%B %Y')
                return shifted.strftime('%d %B %Y')
            if fmt.startswith('%B ') or fmt.startswith('%b '):
                return shifted.strftime('%B %d, %Y')
            return shifted.strftime(fmt)
        except ValueError: pass
    return '[DATE]'

def _phone_digits(value):
    digits=''.join(str(unicodedata.digit(char)) for char in str(value) if char.isdecimal())
    if len(digits)==12 and digits.startswith('91'): digits=digits[2:]
    if len(digits)==11 and digits.startswith('0'): return digits
    if len(digits)==10 and digits.startswith('0'): return digits
    if len(digits)==10 and digits[0] in '6789': return digits
    if len(digits)>=7 and len(digits)<=8: return digits
    return ''

def evidence(obj):
    """Only explicit hospital identifiers; never infer identity from public registries."""
    ids=set()
    def scan(x,k='',depth=0):
        if depth>40:
            return
        if isinstance(x,dict):
            for a,b in x.items(): scan(b,a,depth+1)
        elif isinstance(x,list):
            for i in x: scan(i,k,depth+1)
        elif isinstance(x,(str,int)):
            s=str(x)
            ids.update(norm(v.group()) for v in ID.finditer(s) if not re.match(r'(?i)^(OPD|POL|PMJAY)',v.group()))
            if kind(k)=='id' and k.lower() not in ('visit_id','bill_no') and len(s)>3: ids.add(norm(s))
            key=norm(k)
            contact_type=''
            if 'aadhaar' in key or 'aadhar' in key: contact_type='aadhaar'
            elif 'abha' in key: contact_type='abha'
            elif 'pan' in key and key not in ('panels',): contact_type='pan'
            elif any(part in key for part in ('email','mailaddress')): contact_type='email'
            elif any(part in key for part in ('phone','mobile','telephone','contactnumber','contactno')): contact_type='phone'
            elif any(part in key for part in ('insurance','pmjay','policyno')): contact_type='insurance'
            if contact_type:
                value=s.strip()
                if contact_type=='phone':
                    value=_phone_digits(value)
                elif contact_type in ('aadhaar','abha'):
                    value=re.sub(r'\D','',value)
                    if contact_type=='aadhaar' and len(value)!=12: value=''
                    elif contact_type=='abha' and len(value) not in (14,): value=''
                elif contact_type=='email':
                    value=value.casefold()
                    if not re.fullmatch(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',value): value=''
                elif contact_type=='pan':
                    value=re.sub(r'\s','',value).upper()
                    if not re.fullmatch(r'[A-Z]{5}\d{4}[A-Z]',value): value=''
                else:
                    value=re.sub(r'\s','',value).upper()
                    if len(value)<6: value=''
                if value:
                    ids.add('contact:'+contact_type+':'+token('LINK_'+contact_type,value,32))
            elif isinstance(x,str):
                for match in PHONE.finditer(s):
                    value=_phone_digits(match.group())
                    if value:
                        ids.add('contact-text:phone:'+token('LINK_phone',value,32))
    scan(obj)
    return ids
class Sanitizer:
    def __init__(self, aliases, policy):
        self.aliases=aliases
        self.identity_aliases=getattr(aliases,'identity_signatures',set())
        self.single_aliases=getattr(aliases,'single_signatures',set())
        self.policy=policy
        self.detected=0
        self.generalized=0
        self.suppressed=0
    def redact(self,replacement='[REDACTED]'):
        self.detected+=1
        return replacement
    def text(self,s,patient=None,days=0,monthfirst=False,suppress_quasi=False):
        s=re.sub(
            r'((?:मरीज़|रोगी|मरीज)\s*का\s*नाम)\s*[^\n\r,;.!?]{2,80}',
            lambda m:m.group(1)+' '+self.redact(patient or '[NAME]'),
            s
        )
        s=re.sub(
            r'(?i)\b(her|his)\s+(son|daughter|wife|husband)\s+'
            r'([\w\u0900-\u097f][\w\u0900-\u097f.\-]*'
            r'(?:[\s]+[\w\u0900-\u097f][\w\u0900-\u097f.\-]*){0,2})',
            lambda m:m.group(1)+' '+m.group(2)+' '+self.redact(patient or '[NAME]'),
            s
        )
        s=re.sub(
            r'(?m)((?:मरीज़|रोगी|मरीज)\s+का\s+नाम\s*)([^\n\r,;]{2,80})',
            lambda m:m.group(1)+self.redact(patient or '[NAME]'),
            s
        )
        def relation_names(match):
            patient_name=match.group('patient')
            relative_name=match.group('relative')
            patient_sig=canonical_tokens(patient_name)
            relative_sig=canonical_tokens(relative_name)
            redact_patient=patient_sig in self.identity_aliases or patient_sig in self.single_aliases
            redact_relative=relative_sig in self.identity_aliases or relative_sig in self.single_aliases
            if not redact_patient and not redact_relative:
                return match.group()
            start_patient,end_patient=match.span('patient')
            start_relative,end_relative=match.span('relative')
            result=match.group()
            replacements=[]
            if redact_patient:
                replacements.append((start_patient-match.start(),end_patient-match.start(),self.redact(patient or '[NAME]')))
            if redact_relative:
                replacements.append((start_relative-match.start(),end_relative-match.start(),self.redact()))
            for start,end,replacement in sorted(replacements,reverse=True):
                result=result[:start]+replacement+result[end:]
            return result
        def label(m):
            pre,val=m.groups()
            if not val.strip(): return m.group()
            if norm(pre) in ('district','districtname','jila','tehsil','जिला','तहसील'):
                if not suppress_quasi and self.policy.get('location_level')!='suppressed':
                    return m.group()
                self.generalized+=1
                self.suppressed+=1
                return pre+self.redact()
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
        s=RELATIVE_PAIR.sub(relation_names,s)
        s=re.sub(r'(?im)(\baddress\s*[:.]?\s+)[^\r\n]+',lambda m:m[1]+self.redact(),s)
        s=LABEL.sub(label,s)
        s=ID.sub(lambda m:self.redact(patient or '[ID]'),s)
        s=PLAIN_ID.sub(lambda m:self.redact(patient or '[ID]'),s)
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
        for pattern in getattr(self.aliases,'text_patterns',self.aliases):
            s=pattern.sub(lambda m:m.group() if re.search(r'(?i)Dr\.?\s*$',s[max(0,m.start()-5):m.start()]) else self.redact(patient or '[NAME]'),s)
        if self.identity_aliases:
            words=list(re.finditer(r'[\w\u0900-\u097f]+',s))
            matches=[]
            lengths={len(signature) for signature in self.identity_aliases}
            for size in lengths:
                for start in range(max(0,len(words)-size+1)):
                    span=words[start:start+size]
                    signature=tuple(sorted(token for word in span for token in canonical_tokens(word.group())))
                    if signature not in self.identity_aliases:
                        continue
                    left=span[0].start(); right=span[-1].end()
                    if re.search(r'(?i)Dr\.?\s*$',s[max(0,left-5):left]):
                        continue
                    matches.append((left,right))
            selected=[]
            for left,right in sorted(set(matches),key=lambda item:(item[0],-(item[1]-item[0]))):
                if any(left<end and right>start for start,end in selected):
                    continue
                selected.append((left,right))
            for left,right in sorted(selected,reverse=True):
                s=s[:left]+self.redact(patient or '[NAME]')+s[right:]
        s=re.sub(r'(?i)(?<!\w)[^\W\d_]+(?=\s+(?:sahab|bhai|behenji|amma|didi|ji|babu)\b)',lambda m:self.redact(patient or '[NAME]'),s)
        honorific_name=re.compile(
            r'(?i)(?<!\w)(?:mr|mrs|ms|miss|smt|shrimati|shr?i|pt)\.?\s+'
            r'([A-Z\u0900-\u097f][\w\u0900-\u097f-]*(?:\s+[A-Z\u0900-\u097f][\w\u0900-\u097f-]*){0,2})'
        )
        s=honorific_name.sub(
            lambda m:m.group(0).split()[0]+' '+self.redact(patient or '[NAME]')
            if m.group(0).lower().startswith(('dr','doctor'))
            else self.redact(patient or '[NAME]'),
            s
        )
        s=re.sub(
            r'(?i)\b(?:her|his)\s+(?:son|daughter|wife|husband)\s+'
            r'([\w\u0900-\u097f][\w\u0900-\u097f.\-]*(?:[\s]+[\w\u0900-\u097f][\w\u0900-\u097f.\-]*){0,2})',
            lambda m:re.sub(r'\b'+re.escape(m.group(1))+r'\b',self.redact(patient or '[NAME]'),m.group()),
            s
        )
        s=re.sub(
            r'(?m)(?<![\w])(?:मरीज़|रोगी|मरीज)(?:\s+का\s+नाम|\s*का\s*नाम)\s*(?:है)?\s*[:=]?\s*'
            r'([^\n,;]{2,80})',
            lambda m:m.group(0).replace(m.group(1),self.redact(patient or '[NAME]')),
            s
        )
        s=re.sub(
            r'(?m)(?:पति|पत्नी|पिता|माता|guardian)\s*[:=]\s*([^\n,;]{2,80})',
            lambda m:m.group(0).replace(m.group(1),self.redact()),
            s
        )
        s=re.sub(r'(?im)(\b(?:address|ग्राम|पता)\s*:\s*)[^\r\n]+',lambda m:m[1]+self.redact(),s)
        return s
    def value(self,x,k='',patient=None,days=0,monthfirst=False,path=(),suppress_quasi=False):
        typ=kind(k)
        if isinstance(x,dict):
            if norm(k)=='byname':
                return {f'entry_{i}':self.value(v,'patientref',patient,days,monthfirst,path+(k,),suppress_quasi) for i,v in enumerate(x.values())}
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
                elif norm(a)=='div' and isinstance(b,str):
                    cleaned=self.value(b,a,patient,days,monthfirst,path+(k,),suppress_quasi)
                    out[key]=re.sub(
                        r'(?i)<div\b[^>]*>',
                        '<div xmlns="http://www.w3.org/1999/xhtml">',
                        cleaned,
                        count=1
                    )
                else:
                    out[key]=self.value(b,a,patient,days,monthfirst,path+(k,),suppress_quasi)
            return out
        if isinstance(x,list):
            return [self.value(v,k,patient,days,monthfirst,path,suppress_quasi) for v in x]
        if x is None or isinstance(x,bool) or x=='': return x
        # FHIR structural UUIDs are transformed atomically by the bundle guard;
        # generic numeric regexes must not partially corrupt these references.
        if isinstance(x,str) and 'bundle' in path and norm(k) in ('id','fullurl','reference','value'):
            if re.fullmatch(r'(?i)(?:(?:urn:uuid:|[A-Za-z]+/))?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',x):
                return x
        if norm(k)=='text' and 'name' in tuple(map(norm,path)) and isinstance(x,str):
            return self.redact(patient or '[NAME]')
        if norm(k)=='div' and isinstance(x,str):
            # Keep the XHTML wrapper and generalize demographic narrative.
            x=re.sub(r'(?i)(<div\b[^>]*>)[^<,]+(?=,)',lambda m:m[1]+self.redact(patient or '[NAME]'),x,count=1)
            x=re.sub(r'(?i)\b(\d{1,3})\s*(yrs?|years?)\b',lambda m:band(int(m[1]),self.policy.get('age_band_width',5),self.policy.get('age_top_code',90))+' '+m[2],x)
            x=ID.sub(lambda m:self.redact(patient or '[ID]'),x)
            x=PLAIN_ID.sub(lambda m:self.redact(patient or '[ID]'),x)
            x=PHONE.sub(lambda m:self.redact(),x)
            return x
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
        if typ=='district':
            if suppress_quasi or self.policy.get('location_level')=='suppressed':
                self.generalized+=1
                self.suppressed+=1
                return self.redact() if isinstance(x,str) else None
            return x
        if isinstance(x,str): return self.text(x,patient,days,monthfirst,suppress_quasi)
        return x
def alias_patterns(items):
    names=set()
    full_names=set()
    def visit(x,k=''):
        if isinstance(x,dict):
            for a,b in x.items(): visit(b,a)
        elif isinstance(x,list):
            for v in x: visit(v,k)
        elif isinstance(x,str):
            if kind(k) in ('name','relative') and 3<=len(x)<=80:
                value=x.strip()
                names.add(value)
                if norm(k) not in {'first','firstname','given','givenname','last','lastname','family','familyname','surname'}:
                    full_names.add(value)
                names.update(p for p in re.findall(r'[^\W\d_]+',value, re.UNICODE) if len(p)>=3)
            for m in LABEL.finditer(x):
                if norm(m[1]) in ('name','patientname','नाम','relative name','guardian','so','wo','do'):
                    value=m[2].strip()
                    names.add(value)
                    full_names.add(value)
    for x in items: visit(x)
    return AliasPatterns(names,full_names)
