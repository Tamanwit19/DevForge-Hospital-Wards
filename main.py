"""Parse input files in memory and export a defensive baseline."""
import argparse,csv,io,json,os,time,sys,re
from pathlib import Path
from ingest import walk,sha256_file,decode_bytes,KNOWN
from privacy import Sanitizer,alias_patterns,evidence,norm,kind,band,ID,PHONE,OTHER
from crypto import pseudonym,date_shift_days
from linkage import InternalLinks
from fhir_guard import validate_bundle,clean_attachments,remap_bundle_uuids

def parse(p,max_file_mb=20):
    if p.stat().st_size>max_file_mb*1024*1024: raise ValueError()
    raw=p.read_bytes()
    if not raw: raise ValueError()
    s=decode_bytes(raw).replace('\r\r\n','\n')
    if p.suffix.lower()=='.json':
        def object_pairs(pairs):
            result={}
            for k,v in pairs:
                if k in result: raise ValueError('duplicate_json_key')
                result[k]=v
            return result
        def invalid_constant(_): raise ValueError('nonfinite_json_number')
        return 'json',json.loads(s,object_pairs_hook=object_pairs,parse_constant=invalid_constant)
    if p.suffix.lower() in ('.csv','.tsv'):
        delimiter='\t' if p.suffix.lower()=='.tsv' else ','
        if s.lstrip().startswith(('{','[')): raise ValueError()
        rows=list(csv.reader(io.StringIO(s,newline=''),delimiter=delimiter,strict=True))
        if not rows or not rows[0] or len(set(rows[0]))!=len(rows[0]) or any(len(r)!=len(rows[0]) for r in rows[1:]): raise ValueError()
        return 'csv',(rows[0],rows[1:],delimiter)
    return 'text',s
def units(fmt,data):
    if fmt=='csv':
        h,rows,_=data
        return [(f'row:{i}',dict(zip(h,r))) for i,r in enumerate(rows)]
    if fmt=='json':
        if isinstance(data,list): return [(f'/{i}',v) for i,v in enumerate(data)]
        if isinstance(data,dict) and data.get('resourceType')!='Bundle':
            collections=('patients','visits','reports','records','results','encounters','items','documents')
            groups=[(f'/{k}/{i}',v) for k in collections if isinstance(data.get(k),list)
                    for i,v in enumerate(data[k])]
            if groups: return groups
    return [('doc',data)]

def quasi_values(record,policy):
    ages=set(); districts=set()
    def scan(value,key='',depth=0):
        if depth>40: return
        if isinstance(value,dict):
            for child_key,child in value.items(): scan(child,child_key,depth+1)
        elif isinstance(value,list):
            for child in value: scan(child,key,depth+1)
        elif kind(key)=='age':
            match=re.search(r'\d{1,3}',str(value))
            if match:
                age=int(match.group())
                if 0<=age<=120:
                    ages.add(band(age,policy.get('age_band_width',5),policy.get('age_top_code',90)))
        elif kind(key)=='district' and isinstance(value,str) and value.strip():
            districts.add(norm(value))
    scan(record)
    if len(ages)==1 and len(districts)==1:
        return next(iter(ages)),next(iter(districts))
    return None

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--input',required=True);ap.add_argument('--output',required=True);ap.add_argument('--policy',default=None)
    a=ap.parse_args(); t=time.monotonic()
    if not os.getenv('RAKSHA_SECRET'): sys.exit('RAKSHA_SECRET required')
    def cli_path(s):
        # The kit uses POSIX single-quote shell escaping even on Windows.
        return s[1:-1] if os.name=='nt' and len(s)>1 and s[0]==s[-1]==chr(39) else s
    src=Path(cli_path(a.input)).resolve(); out=Path(cli_path(a.output)).resolve()
    if not src.is_dir(): sys.exit('Input directory does not exist')
    if src==out or src in out.parents or out in src.parents: sys.exit('Input and output must be separate')
    if out.exists() and any(out.iterdir()): sys.exit('Output must be empty')
    (out/'sanitized').mkdir(parents=True,exist_ok=True)
    files=[]; records=[]; parsed=[]; aliases=[]; counts=dict.fromkeys(['files_total','files_sanitized','files_quarantined','records_processed','identifiers_detected','records_linked','records_generalized','records_suppressed','records_quarantined'],0)
    try:
        import yaml
    except ImportError:
        sys.exit('PyYAML is required to load the privacy policy')
    policy_path=Path(a.policy) if a.policy else Path(__file__).parent/'config'/'policy.yaml'
    try:
        policy=yaml.safe_load(policy_path.read_text(encoding='utf-8')) or {}
    except (OSError,yaml.YAMLError):
        sys.exit('Cannot load privacy policy')
    if not isinstance(policy,dict):
        sys.exit('Privacy policy must contain a YAML mapping')
    for p,rel in walk(str(src)):
        p=Path(p); counts['files_total']+=1
        if p.is_symlink(): sys.exit('Symbolic links are unsupported in input')
        ent={'input_sha256':sha256_file(p),'output':None,'status':'quarantined'}
        files.append(ent)
        try:
            if p.is_symlink() or p.suffix.lower() not in KNOWN: raise ValueError()
            fmt,data=parse(p,policy.get('max_file_mb',20)); us=units(fmt,data); parsed.append((p,Path(rel),ent,fmt,data,us))
            if 'registration' in Path(rel).parts: aliases.extend(v for _,v in us)
            if fmt=='text': aliases.append(data)
        except (ValueError,UnicodeError,RecursionError,csv.Error,OSError): ent['reason']='unsupported_or_invalid';counts['files_quarantined']+=1
    san=Sanitizer(alias_patterns(aliases),policy)
    registration_records=[v for _,rel,_,_,_,us in parsed if rel.parts[0]=='registration' for _,v in us]
    links=InternalLinks((evidence(v) for _,_,_,_,_,us in parsed for _,v in us),registration_records)
    cohorts={}
    sparse_patients=set()
    for record in registration_records:
        patient=links.resolve(evidence(record),record)
        signature=quasi_values(record,policy)
        if patient and signature:
            cohorts.setdefault(signature,set()).add(patient)
    threshold=max(2,int(policy.get('rare_value_k',5)))
    for signature,patients in cohorts.items():
        if len(patients)<threshold:
            sparse_patients.update(patients)
    for idx,(p,rel,ent,fmt,data,us) in enumerate(parsed):
        # Preserve the input folder layout. Rename only path components that
        # contain identifiers or names learned from registration records.
        parts=[]
        for i,component in enumerate(rel.parts):
            if i==len(rel.parts)-1:
                stem=p.stem
                identifier_search=stem.replace('_',' ')
                name_search=identifier_search.replace('-',' ')
                sensitive=bool(ID.search(identifier_search) or PHONE.search(identifier_search) or OTHER.search(identifier_search))
                sensitive=sensitive or any(pattern.search(name_search) for pattern in san.aliases)
                parts.append(f'doc_{idx:05d}{p.suffix.lower()}' if sensitive else component)
            else:
                identifier_search=component.replace('_',' ')
                name_search=identifier_search.replace('-',' ')
                sensitive=bool(ID.search(identifier_search) or PHONE.search(identifier_search) or OTHER.search(identifier_search))
                sensitive=sensitive or any(pattern.search(name_search) for pattern in san.aliases)
                parts.append(f'dir_{i}_{idx:05d}' if sensitive else component)
        dest=Path('sanitized')/Path(*parts)
        target=out/dest; local=[]; changed={}; before=san.detected; generalized=0; suppressed_records=0
        try:
            for loc,v in us:
                ids=evidence(v)
                patient=links.resolve(ids,v)
                days=date_shift_days(patient or pseudonym(ent['input_sha256']),policy.get('date_shift_days',180))
                monthfirst='arogya' in p.name.lower()
                prior=san.generalized
                prior_suppressed=san.suppressed
                suppress_quasi=patient is None or patient in sparse_patients
                if fmt=='csv':
                    # Keep input columns as internal keys. Sanitize header only
                    # at serialization, to avoid losing data when it changes.
                    clean={k:san.value(value,k,patient,days,monthfirst,suppress_quasi=suppress_quasi) for k,value in v.items()}
                else:
                    clean=san.value(v,patient=patient,days=days,monthfirst=monthfirst,suppress_quasi=suppress_quasi)
                generalized+=san.generalized>prior
                suppressed_records+=san.suppressed>prior_suppressed
                if patient and patient not in json.dumps(clean,ensure_ascii=False): patient=None
                changed[loc]=clean
                if rel.parts[0]!='clean': local.append({'file':dest.as_posix(),'loc':loc,'patient':patient})
            if fmt=='text': result=changed['doc']
            elif fmt=='csv':
                h,rows,delim=data; buf=io.StringIO(newline='');w=csv.writer(buf,delimiter=delim,lineterminator='\n')
                headers=[]
                for x in h:
                    contains_pii=bool(ID.search(x) or PHONE.search(x) or OTHER.search(x))
                    contains_pii=contains_pii or any(pattern.search(x) for pattern in san.aliases)
                    cleaned=f'column_{len(headers)}' if contains_pii else x
                    if cleaned in headers: cleaned=f'{cleaned}_{len(headers)}'
                    headers.append(cleaned)
                w.writerow(headers)
                for i,row in enumerate(rows): w.writerow([changed[f'row:{i}'][x] for x in h])
                result=buf.getvalue()
            else:
                if 'doc' in changed:
                    root=changed['doc']
                    if isinstance(root,dict) and root.get('resourceType')=='Bundle':
                        root=remap_bundle_uuids(clean_attachments(root))
                        validate_bundle(root)
                    result=json.dumps(root,ensure_ascii=False,indent=2)
                else:
                    root=san.value(data)
                    for loc,v in changed.items():
                        a=loc.strip('/').split('/')
                        if len(a)==1: root[int(a[0])]=v
                        else: root[a[0]][int(a[1])]=v
                    result=json.dumps(root,ensure_ascii=False,indent=2)
            target.parent.mkdir(parents=True,exist_ok=True);target.write_text(result,encoding='utf-8')
            ent.update(output=dest.as_posix(),status='sanitized')
            counts['files_sanitized']+=1; counts['records_processed']+=len(local)
            counts['records_linked']+=sum(r['patient'] is not None for r in local)
            counts['identifiers_detected']+=san.detected-before; counts['records_generalized']+=generalized;records.extend(local)
            counts['records_suppressed']+=suppressed_records
        except (ValueError,TypeError,KeyError,RecursionError,OSError):
            ent['reason']='processing_failed';counts['files_quarantined']+=1
    (out/'records.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in records),encoding='utf-8')
    rss=0
    try:
        import resource
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
    except ImportError:
        try:
            import psutil
            rss=psutil.Process().memory_info().peak_wset/1048576
        except Exception: pass
    (out/'report.json').write_text(json.dumps({'schema':'raksha-report/1','files':files,'counts':counts,'timing':{'seconds':round(time.monotonic()-t,3)},'resources':{'peak_rss_mb':rss}},indent=2),encoding='utf-8')
    print('Processing complete:',counts['files_sanitized'],'sanitized;',counts['files_quarantined'],'quarantined')
if __name__=='__main__': main()
