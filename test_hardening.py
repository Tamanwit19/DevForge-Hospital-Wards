import unittest,os,base64,tempfile,json,subprocess,sys
from pathlib import Path
from linkage import InternalLinks
from identity_normalization import canonical_tokens
from crypto import pseudonym
from fhir_guard import clean_attachments,validate_bundle
from privacy import Sanitizer,evidence
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
    def test_duplicate_registrations_merge_on_full_identity_and_dob(self):
        registrations=[
            {'uhid':'UHID-111117','patient_name':'Anita Sharma','relative_name':'Jagadish Sharma','dob':'1981-01-21','mobile':'9876543210'},
            {'uhid':'JJH-0076957','patient_name':'Anita Sharma','relative_name':'Jagdish Sharma','dob':'1981-01-21','mobile':'9876543210'},
        ]
        links=InternalLinks([evidence(row) for row in registrations],registrations)
        self.assertEqual(links.resolve({'uhid111117'}),links.resolve({'jjh0076957'}))
        contact=next(item for item in evidence(registrations[0]) if item.startswith('contact:phone:'))
        self.assertEqual(links.resolve({contact}),links.resolve({'uhid111117'}))
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
    def test_phone_links_only_when_unique(self):
        registration={'uhid':'UHID-111111','patient_name':'Meera Rajan','mobile':'9876543210'}
        links=InternalLinks([evidence(registration)], [registration])
        contact=next(item for item in evidence(registration) if item.startswith('contact:phone:'))
        self.assertEqual(links.resolve({contact}),links.resolve({'uhid111111'}))
        shared=[
            {'uhid':'UHID-111111','mobile':'9876543210'},
            {'uhid':'UHID-222222','mobile':'9876543210'},
        ]
        ambiguous=InternalLinks([evidence(row) for row in shared], shared)
        contact=next(item for item in evidence(shared[0]) if item.startswith('contact:phone:'))
        self.assertIsNone(ambiguous.resolve({contact}))
    def test_free_text_phone_needs_unique_owner_matching_name_and_age(self):
        registration={'uhid':'UHID-111114','patient_name':'Asha Rajput','age':48,'mobile':'8069773173'}
        note='Report of Asha ji 48 Y / F. Contact 8069773173'
        links=InternalLinks([evidence(registration),evidence(note)],[registration])
        self.assertEqual(links.resolve(evidence(note),note),
                         links.resolve(evidence(registration),registration))
        mismatch='Report of Reena ji 65 Y / F. Contact 8069773173'
        self.assertIsNone(links.resolve(evidence(mismatch),mismatch))
        shared={'uhid':'UHID-111115','patient_name':'Asha Rajput','age':48,'mobile':'8069773173'}
        ambiguous=InternalLinks([evidence(registration),evidence(shared),evidence(note)],
                                [registration,shared])
        self.assertIsNone(ambiguous.resolve(evidence(note),note))
        deva_phone='\u096f\u096e\u096d\u096c\u096b\u096a\u0969\u0967\u096d\u096f'
        self.assertEqual(evidence({'mobile':deva_phone}),
                         evidence({'mobile':'9876543179'}))
    def test_cross_script_name_and_relative_link(self):
        registration={
            'uhid':'UHID-111111',
            'patient_name':'Mohammad Arif',
            'relative_name':'Ramesh',
            'age':47,
        }
        note={'text':'मोहम्मद आरिफ, W/o Ramesh'}
        links=InternalLinks([evidence(registration)], [registration])
        self.assertEqual(links.resolve(evidence(note),note),
                         links.resolve(evidence(registration),registration))
        self.assertEqual(canonical_tokens('Mohd. Arif'),canonical_tokens('मोहम्मद आरिफ'))
        self.assertEqual(canonical_tokens('Meera'),canonical_tokens('मीरा'))
        self.assertEqual(canonical_tokens('Arif'),canonical_tokens('आरिफ'))
        for latin, devanagari in (
            ('Asha', 'आशा'),
            ('Anita', 'अनिता'),
            ('Farida', 'फरीदा'),
            ('Shanti', 'शान्ति'),
            ('Nishad', 'निषाद'),
        ):
            self.assertEqual(canonical_tokens(latin), canonical_tokens(devanagari))
    def test_fragmented_first_name_and_relative_links_to_full_registration_name(self):
        registration={'uhid':'UHID-111112','patient_name':'Meera Sharma','relative_name':'Rajan'}
        note='Meera, W/o Rajan'
        links=InternalLinks([evidence(registration)],[registration])
        self.assertEqual(links.resolve(evidence(note),note),
                         links.resolve(evidence(registration),registration))
    def test_relative_pair_does_not_capture_preceding_line(self):
        registration={'uhid':'UHID-111116','patient_name':'Asha Rajput','relative_name':'Kamal'}
        note='Discharge note\n\nAsha, W/o Kamal'
        links=InternalLinks([evidence(registration)],[registration])
        self.assertEqual(links.resolve(evidence(note),note),
                         links.resolve(evidence(registration),registration))
    def test_hindi_name_age_village_links_across_transliteration_variant(self):
        registration={'uhid':'UHID-111113','patient_name':'Reena Nishad','age':65,'village':'Bhimnagar'}
        note=(
            '\u0928\u093e\u092e: \u0930\u0940\u0928\u093e \u0928\u093f\u0937\u093e\u0926  '
            '\u0906\u092f\u0941: 65 \u0935\u0930\u094d\u0937\n'
            '\u0917\u094d\u0930\u093e\u092e: \u092d\u0940\u092e\u0928\u0917\u0930'
        )
        links=InternalLinks([evidence(registration)],[registration])
        self.assertEqual(links.resolve(evidence(note),note),
                         links.resolve(evidence(registration),registration))
    def test_event_date_adjusts_age_using_registered_dob(self):
        registration={
            'uhid':'UHID-111118',
            'patient_name':'Sukhwinder Kaur',
            'age':41,
            'dob':'1982-01-22',
            'village':'Durgamau Kalan',
        }
        note=(
            'नाम: सुखविंदर कौर   आयु: 44 वर्ष\n'
            'ग्राम: दुर्गामऊ कलां\n'
            'तारीख: 16/05/2026'
        )
        links=InternalLinks([evidence(registration)],[registration])
        self.assertEqual(links.resolve(evidence(note),note),
                         links.resolve(evidence(registration),registration))
        without_date=note.replace('\nतारीख: 16/05/2026','')
        self.assertIsNone(links.resolve(evidence(without_date),without_date))
    def test_name_only_does_not_link(self):
        registration={'uhid':'UHID-111111','patient_name':'Ramesh Kumar'}
        note={'patient_name':'Ramesh Kumar'}
        links=InternalLinks([evidence(registration)], [registration])
        self.assertIsNone(links.resolve(evidence(note),note))
    def test_fuzzy_name_requires_a_matching_relative_and_unique_owner(self):
        registration={'uhid':'UHID-111111','patient_name':'Mohammad Arif','relative_name':'Ramesh'}
        links=InternalLinks([evidence(registration)], [registration])
        typo={'patient_name':'Mohammd Arif','relative_name':'Ramesh'}
        self.assertEqual(links.resolve(evidence(typo),typo),
                         links.resolve(evidence(registration),registration))
        other={'uhid':'UHID-222222','patient_name':'Mohammad Arif','relative_name':'Ramesh'}
        ambiguous=InternalLinks([evidence(registration),evidence(other)],[registration,other])
        self.assertIsNone(ambiguous.resolve(evidence(typo),typo))
    def test_cross_script_name_redaction_keeps_doctor_and_clinical_values(self):
        from privacy import alias_patterns
        aliases=alias_patterns([{'patient_name':'Mohammad Arif'}])
        sanitizer=Sanitizer(aliases,{})
        clean=sanitizer.text('Dr. Mohammad Arif reviewed Mohammad Arif. मोहम्मद आरिफ: BP 120/80')
        self.assertIn('Dr. Mohammad Arif',clean)
        self.assertNotIn('Mohammad Arif. मोहम्मद आरिफ',clean)
        self.assertIn('BP 120/80',clean)
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
    def test_sparse_cohort_suppresses_location_not_truthful_age_band(self):
        s=Sanitizer([],{'age_band_width':5,'age_top_code':90})
        self.assertEqual(s.value({'age':'47','district':'Example District'},suppress_quasi=True),
                         {'age':'45-49','district':'[REDACTED]'})
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
