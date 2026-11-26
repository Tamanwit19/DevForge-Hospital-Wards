"""Optional offline full-schema check using a locally provided schema document.
No network resolution, no patient field values in diagnostics.
"""
import argparse,json
from pathlib import Path

def validate_release_schema(output,schema_path):
    from jsonschema.validators import validator_for
    from referencing import Registry
    schema=json.loads(Path(schema_path).read_text(encoding='utf-8'))
    cls=validator_for(schema)
    cls.check_schema(schema)
    validator=cls(schema,registry=Registry())
    checked=failed=0
    for p in sorted((Path(output)/'sanitized'/'fhir').glob('*.json')):
        checked+=1
        doc=json.loads(p.read_text(encoding='utf-8'))
        if not validator.is_valid(doc): failed+=1
    return {'bundles_checked':checked,'bundles_failed':failed,
            'bundles_passed':checked-failed,'scope':'Provided local JSON Schema only; profile and terminology validation may require additional checks.'}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output',required=True)
    p.add_argument('--schema',required=True)
    a=p.parse_args()
    try: result=validate_release_schema(a.output,a.schema)
    except Exception: p.exit(1,'Schema check could not run; use a self-contained local schema and install optional validation dependencies.\n')
    print(json.dumps(result,indent=2))
    raise SystemExit(1 if result['bundles_failed'] or not result['bundles_checked'] else 0)
