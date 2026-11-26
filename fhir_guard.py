"""FHIR structural safeguards (not comprehensive R4 schema validation)."""
import base64
import re
import xml.etree.ElementTree as ET
from crypto import resource_uuid

def validate_bundle(bundle):
    if not isinstance(bundle,dict) or bundle.get('resourceType')!='Bundle':
        return
    entries=bundle.get('entry',[])
    if not isinstance(entries,list):
        raise ValueError('invalid_bundle_entries')
    urls=set()
    local_resources=set()
    for entry in entries:
        if not isinstance(entry,dict) or not isinstance(entry.get('resource'),dict):
            raise ValueError('invalid_bundle_entry')
        resource=entry['resource']
        rt=resource.get('resourceType')
        rid=resource.get('id')
        if not isinstance(rt,str) or not re.fullmatch(r'[A-Z][A-Za-z]+',rt):
            raise ValueError('invalid_resource_type')
        if rid is not None:
            if not isinstance(rid,str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,64}',rid):
                raise ValueError('invalid_resource_id')
            local_key=f'{rt}/{rid}'
            if local_key in local_resources: raise ValueError('duplicate_resource_identity')
            local_resources.add(local_key)
        full=entry.get('fullUrl')
        if full:
            if full in urls: raise ValueError('duplicate_bundle_reference')
            urls.add(full)
    def visit(x):
        if isinstance(x,dict):
            if 'contentType' in x and 'data' in x:
                try: base64.b64decode(x['data'],validate=True)
                except (ValueError,TypeError) as exc: raise ValueError('invalid_attachment_encoding') from exc
            if 'div' in x and isinstance(x['div'],str):
                try:
                    node=ET.fromstring(x['div'])
                    if node.tag!='{http://www.w3.org/1999/xhtml}div': raise ValueError('invalid_fhir_narrative_root')
                except ET.ParseError as exc:
                    raise ValueError('invalid_fhir_narrative') from exc
            ref=x.get('reference')
            if isinstance(ref,str) and ref.startswith('urn:uuid:') and ref not in urls:
                raise ValueError('unresolved_bundle_reference')
            if isinstance(ref,str) and bundle.get('type')=='document' and re.fullmatch(r'[A-Z][A-Za-z]+/[A-Za-z0-9.-]{1,64}',ref) and ref not in local_resources:
                raise ValueError('unresolved_relative_reference')
            for v in x.values(): visit(v)
        elif isinstance(x,list):
            for v in x: visit(v)
    visit(bundle)

def clean_attachments(obj):
    """Remove raw opaque attachments rather than exposing decoded content.
    Retain an encoded, harmless marker with a valid base64 representation.
    """
    if isinstance(obj,dict):
        if obj.get('resourceType')=='Patient':
            obj=dict(obj)
            # birthDate is optional; a redaction marker is not a valid FHIR date.
            obj.pop('birthDate',None)
        if 'contentType' in obj and any(k in obj for k in ('data','url','hash','size','title')):
            obj=dict(obj)
            if 'data' in obj:
                obj['data']=base64.b64encode(b'[ATTACHMENT REMOVED]').decode('ascii')
                obj['contentType']='text/plain'
            for field in ('url','hash','size','title'):
                obj.pop(field,None)
        return {k:clean_attachments(v) for k,v in obj.items()}
    if isinstance(obj,list): return [clean_attachments(v) for v in obj]
    return obj


UUID_PATTERN=re.compile(r'(?i)(?<![0-9a-f])(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![0-9a-f])')

def remap_bundle_uuids(bundle):
    """Re-key only resource UUIDs declared in a bundle, preserving references.
    Unrelated clinical coding values are not treated as identifiers.
    """
    ids=set()
    def add(value):
        if isinstance(value,str):
            ids.update(m.group().lower() for m in UUID_PATTERN.finditer(value))
    add(bundle.get('id'))
    for entry in bundle.get('entry',[]):
        add(entry.get('fullUrl'))
        resource=entry.get('resource',{})
        add(resource.get('id'))
    mapping={v:resource_uuid(v) for v in ids}
    def walk(x):
        if isinstance(x,dict): return {k:walk(v) for k,v in x.items()}
        if isinstance(x,list): return [walk(v) for v in x]
        if isinstance(x,str): return UUID_PATTERN.sub(lambda m:mapping.get(m.group().lower(),m.group()),x)
        return x
    return walk(bundle)
