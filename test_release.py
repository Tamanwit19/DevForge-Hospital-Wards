"""Independent synthetic fixtures; never read the organizer truth file."""
import base64,io,json,os,tempfile,unittest,zipfile
from pathlib import Path
from crypto import resource_uuid
from fhir_guard import clean_attachments,remap_bundle_uuids,validate_bundle
from main import parse
from privacy import Sanitizer
from privacy_audit import audit
from secure_archive import encrypt_release,decrypt_bytes

class ReleaseTests(unittest.TestCase):
    def setUp(self): os.environ['RAKSHA_SECRET']='fixture-key'
    def test_unseen_structured_aliases(self):
        x={'full_name':'Example Person','contact_no':'private-contact','medical_record_number':'NEW-12345','age_years':47,'residential_address':'Example Address','lab_value':13.2}
        clean=Sanitizer([],{}).value(x)
        for value in ('Example Person','private-contact','NEW-12345','Example Address'):
            self.assertNotIn(value,json.dumps(clean))
        self.assertEqual(clean['lab_value'],13.2)
    def test_multiple_json_collections(self):
        from main import units
        data={'patients':[{'name':'Example Person'}],'encounters':[{'uhid':'UHID-123456'}]}
        self.assertEqual([loc for loc,_ in units('json',data)],['/patients/0','/encounters/0'])
    def test_json_duplicate_and_nonfinite(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'fixture.json'
            for payload in ('{"name":"a","name":"b"}','{"value":NaN}'):
                p.write_text(payload,encoding='utf-8')
                with self.assertRaises(ValueError):parse(p)
    def test_fhir_rekey_and_reference(self):
        a='aaaaaaaa-bbbb-4ccc-8ddd-123456789012'
        b='bbbbbbbb-aaaa-4ccc-8ddd-987654321098'
        bundle={'resourceType':'Bundle','type':'document','entry':[
            {'fullUrl':'urn:uuid:'+a,'resource':{'resourceType':'Patient','id':a}},
            {'fullUrl':'urn:uuid:'+b,'resource':{'resourceType':'Observation','id':b,'subject':{'reference':'urn:uuid:'+a},'valueQuantity':{'value':12.3,'unit':'mg/dL'}}}]}
        sanitized=Sanitizer([],{}).value(bundle)
        out=remap_bundle_uuids(clean_attachments(sanitized))
        validate_bundle(out)
        self.assertEqual(out['entry'][1]['resource']['subject']['reference'],out['entry'][0]['fullUrl'])
        self.assertEqual(out['entry'][1]['resource']['valueQuantity']['value'],12.3)
        self.assertNotIn(a,json.dumps(out))
        self.assertEqual(out,remap_bundle_uuids(clean_attachments(sanitized)))
        os.environ['RAKSHA_SECRET']='second-fixture-key'
        self.assertNotEqual(out,remap_bundle_uuids(clean_attachments(sanitized)))
    def test_fhir_local_reference_validation(self):
        bundle={'resourceType':'Bundle','type':'document','entry':[{'resource':{'resourceType':'Observation','id':'o1','subject':{'reference':'Patient/p1'}}}]}
        with self.assertRaises(ValueError):validate_bundle(bundle)
    def test_attachment_mime(self):
        result=clean_attachments({'contentType':'application/pdf','data':'c2VjcmV0'})
        self.assertEqual(result['contentType'],'text/plain')
        self.assertEqual(base64.b64decode(result['data']),b'[ATTACHMENT REMOVED]')
    def test_optional_local_schema(self):
        from validate_fhir_schema import validate_release_schema
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);f=root/'sanitized'/'fhir';f.mkdir(parents=True)
            (f/'ok.json').write_text('{"resourceType":"Bundle"}')
            (f/'bad.json').write_text('{"resourceType":"Patient"}')
            schema=root/'schema.json'
            schema.write_text(json.dumps({"type":"object","properties":{"resourceType":{"const":"Bundle"}},"required":["resourceType"]}))
            result=validate_release_schema(root,schema)
            self.assertEqual(result['bundles_failed'],1)
            self.assertEqual(result['bundles_passed'],1)
    def test_archive(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'release'; root.mkdir(); (root/'sanitized').mkdir()
            (root/'sanitized'/'fixture.txt').write_text('synthetic clinical fixture',encoding='utf-8')
            (root/'report.json').write_text('{}')
            (root/'records.jsonl').write_text('')
            dst=Path(t)/'fixture.enc'
            key=bytes(range(32));encrypt_release(root,dst,key)
            blob=dst.read_bytes()
            self.assertNotIn(b'synthetic clinical fixture',blob)
            with zipfile.ZipFile(io.BytesIO(decrypt_bytes(blob,key))) as z:
                self.assertEqual(z.read('sanitized/fixture.txt'),b'synthetic clinical fixture')
            from cryptography.exceptions import InvalidTag
            with self.assertRaises(InvalidTag):decrypt_bytes(blob,bytes(reversed(key)))
            with self.assertRaises(FileExistsError):encrypt_release(root,dst,key)
    def test_audit_reports_missing_coverage(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'sanitized'/'registration';p.mkdir(parents=True)
            (p/'fixture.csv').write_text('patient_name,age,district\nPSN-ABCDEFGH,40-44,Example District\nPSN-ABCDEFGJ,40-44,[REDACTED]\n',encoding='utf-8')
            result=audit(t)
            self.assertEqual(result['registration_rows'],2)
            self.assertEqual(result['rows_missing_one_or_more_fields'],1)
            self.assertEqual(result['pseudonyms_with_complete_fields'],1)
            self.assertNotIn('Example District',json.dumps(result))
if __name__=='__main__': unittest.main()
