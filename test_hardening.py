import unittest,os,base64,tempfile,json,subprocess,sys
from pathlib import Path
from linkage import InternalLinks
from crypto import pseudonym
from fhir_guard import clean_attachments,validate_bundle
from privacy import Sanitizer
from main import parse

class HardeningTests(unittest.TestCase):
    def setUp(self): os.environ['RAKSHA_SECRET']='test-secret'
    def test_explicit_encounter_link(self):
        links=InternalLinks([{'uhid111111','adm000111'}])
        self.assertEqual(links.resolve({'adm000111'}),pseudonym('uhid111111'))
    def test_conflicting_encounter(self):
        links=InternalLinks([{'uhid111111','adm000111'},{'uhid222222','adm000111'}])
        self.assertIsNone(links.resolve({'adm000111'}))
    def test_explicit_duplicate_registration(self):
        registrations=[{'uhid':'UHID-111111','aadhaar':'1234 5678 9012'},{'uhid':'UHID-222222','aadhaar':'123456789012'}]
        links=InternalLinks([],registrations)
        self.assertEqual(links.resolve({'uhid111111'}),links.resolve({'uhid222222'}))
    def test_conflicting_registration_not_merged(self):
        registrations=[{'uhid':'UHID-111111','aadhaar':'123456789012'},{'uhid':'UHID-111111','aadhaar':'987654321098'},{'uhid':'UHID-222222','aadhaar':'123456789012'}]
        links=InternalLinks([],registrations)
        self.assertNotEqual(links.resolve({'uhid111111'}),links.resolve({'uhid222222'}))
    def test_masked_registration_not_merged(self):
        registrations=[{'uhid':'UHID-111111','aadhaar':'XXXX XXXX 9012'},{'uhid':'UHID-222222','aadhaar':'XXXX XXXX 9012'}]
        links=InternalLinks([],registrations)
        self.assertNotEqual(links.resolve({'uhid111111'}),links.resolve({'uhid222222'}))
    def test_multiple_patient_ids(self):
        self.assertIsNone(InternalLinks([]).resolve({'uhid111111','uhid222222'}))
    def test_fhir_guard(self):
        b={'resourceType':'Bundle','entry':[{'fullUrl':'urn:uuid:a','resource':{'resourceType':'Patient','birthDate':'1980-01-01'}},{'fullUrl':'urn:uuid:b','resource':{'resourceType':'Observation','subject':{'reference':'urn:uuid:a'}}}]}
        result=clean_attachments(b)
        validate_bundle(result)
        self.assertNotIn('birthDate',result['entry'][0]['resource'])
        result['entry'][1]['resource']['subject']['reference']='urn:uuid:missing'
        with self.assertRaises(ValueError): validate_bundle(result)
    def test_opaque_attachments(self):
        data={'contentType':'text/plain','data':base64.b64encode(b'Example confidential payload').decode(),'title':'private title'}
        clean=clean_attachments(data)
        self.assertEqual(base64.b64decode(clean['data']),b'[ATTACHMENT REMOVED]')
        self.assertNotIn('title',clean)
    def test_policy(self):
        s=Sanitizer([],{'age_band_width':10,'age_top_code':80,'location_level':'suppressed'})
        self.assertEqual(s.value({'age':'47','district':'Example District'}),{'age':'40-49','district':'[REDACTED]'})
        self.assertEqual(s.value({'age':84})['age'],80)
    def test_duplicate_csv_header(self):
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/'bad.csv'
            f.write_text('name,name\na,b\n',encoding='utf-8')
            with self.assertRaises(ValueError): parse(f)
    def test_unseen_formats_end_to_end(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); src=root/'input'; src.mkdir(); out=root/'output'
            (src/'random.csv').write_text('patient_name,uhid,phone,bp\nExample Person,UHID-123456,9876543210,120/80\n',encoding='utf-16')
            (src/'notes.txt').write_text('Patient Name: Example Person\nUHID: UHID-123456\nBP 120/80',encoding='utf-8')
            (src/'broken.json').write_text('{"bad":',encoding='utf-8')
            (src/'unsupported.bin').write_bytes(b'private')
            r=subprocess.run([sys.executable,str(Path(__file__).with_name('main.py')),'--input',str(src),'--output',str(out)],capture_output=True)
            self.assertEqual(r.returncode,0)
            rep=json.loads((out/'report.json').read_text())
            self.assertEqual(rep['counts']['files_quarantined'],2)
            content=''.join(p.read_text(encoding='utf-8') for p in (out/'sanitized').rglob('*') if p.is_file())
            self.assertNotIn('Example Person',content)
            self.assertNotIn('9876543210',content)
            self.assertIn('120/80',content)
if __name__=='__main__': unittest.main()
