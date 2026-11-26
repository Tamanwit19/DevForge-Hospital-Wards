"""Aggregate release audit. Reports only counts, never group values or identifiers."""
import argparse,csv,json,re
from collections import defaultdict
from pathlib import Path

PSN=re.compile(r'PSN-[A-Z2-9]{8}')
def _fields(record,width=5,top=90):
    if not isinstance(record,dict): return None,None
    fields={re.sub(r'[^a-z]','',str(k).lower()):v for k,v in record.items()}
    age=fields.get('age',fields.get('umar'))
    district=fields.get('district',fields.get('jila'))
    if not district and isinstance(fields.get('address'),dict):
        district=fields['address'].get('district')
    if isinstance(age,int): age=f'{age}-{min(top-1,age+width-1)}' if age<top else f'{top}+'
    if not isinstance(age,str) or not re.fullmatch(r'\d{1,3}(?:-\d{1,3}|\+)',age):
        age=None
    if not isinstance(district,str) or not district.strip() or district.startswith('['): district=None
    return age,district
def audit(output,k=5,width=5,top=90):
    root=Path(output)/'sanitized'/'registration'
    cohorts=defaultdict(set)
    seen=set()
    all_pseudonyms=set()
    total_rows=0
    unlinked_rows=0
    partial_rows=0
    suppressed_district_rows=0
    suppressed_age_rows=0
    patients_suppressed_district=set()
    for f in sorted(root.glob('*')):
        if f.suffix in ('.csv','.tsv'):
            with f.open(encoding='utf-8',newline='') as stream:
                rows=list(csv.DictReader(stream,delimiter='\t' if f.suffix=='.tsv' else ','))
        elif f.suffix=='.json':
            obj=json.loads(f.read_text(encoding='utf-8'))
            rows=obj.get('patients',[]) if isinstance(obj,dict) else obj
        else: continue
        for row in rows:
            total_rows+=1
            ids=set(PSN.findall(json.dumps(row,ensure_ascii=False)))
            field_values={re.sub(r'[^a-z]','',str(k).lower()):v for k,v in row.items()}
            if isinstance(field_values.get('district',field_values.get('jila')),str) and str(field_values.get('district',field_values.get('jila'))).startswith('['):
                suppressed_district_rows+=1
                patients_suppressed_district.update(ids)
            age_value=field_values.get('age',field_values.get('umar'))
            if isinstance(age_value,str) and age_value.startswith('['):
                suppressed_age_rows+=1
            if len(ids)!=1:
                unlinked_rows+=1
                continue
            patient=next(iter(ids))
            all_pseudonyms.add(patient)
            age,district=_fields(row,width,top)
            if age is None or district is None:
                partial_rows+=1
                continue
            seen.add(patient)
            cohorts[(age,district)].add(patient)
    small=set()
    for members in cohorts.values():
        if len(members)<k: small.update(members)
    return {'threshold_k':k,'registration_rows':total_rows,'unlinked_or_ambiguous_rows':unlinked_rows,
            'rows_missing_one_or_more_fields':partial_rows,'distinct_registration_pseudonyms':len(all_pseudonyms),
            'cohorts_checked':len(cohorts),'pseudonyms_with_complete_fields':len(seen),
            'pseudonyms_in_small_cohorts':len(small) if cohorts else None,
            'rows_with_suppressed_district':suppressed_district_rows,
            'rows_with_suppressed_age':suppressed_age_rows,
            'pseudonyms_with_suppressed_district':len(patients_suppressed_district),
            'risk_assessment_coverage':'partial' if suppressed_district_rows or partial_rows else 'complete',
            'coverage_note':'Visible registration cohorts only; suppressed or missing fields are not evidence of low risk. Not a proof of anonymity.'}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output',required=True)
    p.add_argument('--k',type=int,default=5)
    p.add_argument('--policy',default=None)
    a=p.parse_args()
    if a.k<2: p.error('k must be at least 2')
    policy={}
    if a.policy:
        import yaml
        policy=yaml.safe_load(Path(a.policy).read_text(encoding='utf-8')) or {}
    print(json.dumps(audit(a.output,a.k,policy.get('age_band_width',5),policy.get('age_top_code',90)),indent=2))
