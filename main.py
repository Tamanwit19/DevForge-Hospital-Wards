"""Parse input files in memory and export a defensive baseline."""
import argparse,csv,io,json,os,time,sys
from pathlib import Path
from ingest import walk,sha256_file,decode_bytes,KNOWN
from privacy import Sanitizer,alias_patterns,evidence,norm,kind,ID
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
        policy=yaml.safe_load((Path(a.policy) if a.policy else Path(__file__).with_name('policy.yaml')).read_text(encoding='utf-8')) or {}
    except (ImportError,OSError):
        if a.policy: sys.exit('Cannot load requested privacy policy')
        policy={}
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
    links=InternalLinks((evidence(v) for _,_,_,_,_,us in parsed for _,v in us),
                        (v for _,rel,_,_,_,us in parsed if rel.parts[0]=='registration' for _,v in us))
    safe_dirs={'registration','lab','billing','clean','discharge','fhir','misc','notes','opd','prescriptions'}
    for idx,(p,rel,ent,fmt,data,us) in enumerate(parsed):
        # Opaque names keep file-name PII out of release; preserve known category.
        category=rel.parts[0] if len(rel.parts)>1 and rel.parts[0] in safe_dirs else 'other'
        dest=Path('sanitized')/category/f'doc_{idx:05d}{p.suffix.lower()}'
        target=out/dest; local=[]; changed={}; before=san.detected; generalized=0
        try:
            for loc,v in us:
                ids=evidence(v)
                patient=links.resolve(ids)
                days=date_shift_days(patient or pseudonym(ent['input_sha256']),policy.get('date_shift_days',180))
                monthfirst='arogya' in p.name.lower()
                prior=san.generalized
                if fmt=='csv':
                    # Keep input columns as internal keys. Sanitize header only
                    # at serialization, to avoid losing data when it changes.
                    clean={k:san.value(value,k,patient,days,monthfirst) for k,value in v.items()}
                else:
                    clean=san.value(v,patient=patient,days=days,monthfirst=monthfirst)
                generalized+=san.generalized>prior
                if patient and patient not in json.dumps(clean,ensure_ascii=False): patient=None
                changed[loc]=clean
                if category!='clean': local.append({'file':dest.as_posix(),'loc':loc,'patient':patient})
            if fmt=='text': result=changed['doc']
            elif fmt=='csv':
                h,rows,delim=data; buf=io.StringIO(newline='');w=csv.writer(buf,delimiter=delim,lineterminator='\n')
                headers=[]
                for x in h:
                    cleaned=f'column_{len(headers)}' if ID.search(x) else san.text(x)
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
