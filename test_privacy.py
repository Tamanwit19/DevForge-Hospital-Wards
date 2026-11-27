import unittest
import os
from privacy import Sanitizer,evidence,band
from crypto import pseudonym,date_shift_days

class PrivacyTests(unittest.TestCase):
    def setUp(self):
        os.environ['RAKSHA_SECRET']='unit-test-only'
        self.s=Sanitizer([],{'age_band_width':5})
    def test_structured(self):
        x={'patient_name':'Example Person','phone':'9876543210','age':'47','bp':'150/90','drug':'Paracetamol 650 mg'}
        y=self.s.value(x,patient='PSN-TEST')
        self.assertEqual(y['patient_name'],'PSN-TEST')
        self.assertEqual(y['phone'],'[REDACTED]')
        self.assertEqual(y['age'],'45-49')
        self.assertEqual(y['bp'],x['bp'])
        self.assertEqual(y['drug'],x['drug'])
    def test_clinical(self):
        x='C/O fever. Dr. Example. BP 150/90. Dolo 650 mg 1-0-1.'
        self.assertEqual(self.s.text(x),x)
    def test_date_interval(self):
        self.assertEqual(self.s.text('2026-01-01 to 2026-01-10',days=4),'2026-01-05 to 2026-01-14')
    def test_keyed_identity(self):
        a=pseudonym('example-id')
        self.assertEqual(a,pseudonym('example-id'))
        os.environ['RAKSHA_SECRET']='another-unit-test'
        self.assertNotEqual(a,pseudonym('example-id'))
    def test_explicit_id(self):
        self.assertEqual(evidence({'uhid':'UHID-123456'}),{'uhid123456'})
    def test_contextual_notes(self):
        for text in ("Example Person ka BP 150/90", "14:00 - Example Person - K/C/O fever", "Sample received from Example Person's attendant", "Called by Example Person 9876543210"):
            clean=self.s.text(text)
            self.assertNotIn('Example Person',clean)
        self.assertIn('150/90',self.s.text('Example Person ka BP 150/90'))
    def test_fhir_sensitive_narrative(self):
        data={'resourceType':'Patient','text':{'div':'<div xmlns="http://www.w3.org/1999/xhtml">Example Person, 47 yrs, female</div>'},'contact':[{'name':{'text':'Example Relative'}}]}
        result=self.s.value(data,patient='PSN-TEST')
        self.assertNotIn('Example Person',str(result))
        self.assertNotIn('Example Relative',str(result))
        self.assertIn('45-49',str(result))
    def test_fhir_narrative_redacts_plain_mrn_core(self):
        data={'resourceType':'Patient','text':{'div':'<div xmlns="http://www.w3.org/1999/xhtml">Patient MRN 064127, 47 yrs</div>'}}
        result=self.s.value(data,patient='PSN-TEST')
        self.assertNotIn('064127',str(result))
    def test_identity_key_map(self):
        result=self.s.value({'by_name':{'Example Person':'UHID-12345','Another Person':'UHID-54321'}})
        self.assertEqual(len(result['by_name']),2)
        self.assertNotIn('Example Person',str(result))
    def test_unseen_honorific_names_and_relations(self):
        text='Mr. Imran Qureshi met Smt. Kamla Bai. her son Arjun Nair. मरीज़ का नाम दीपक शर्मा है.'
        clean=self.s.text(text)
        for value in ('Imran Qureshi','Kamla Bai','Arjun Nair','दीपक शर्मा'):
            self.assertNotIn(value,clean)
    def test_landline_numbers(self):
        text='Call 080-2345678 or 0522-2234567.'
        clean=self.s.text(text)
        self.assertNotIn('080-2345678',clean)
        self.assertNotIn('0522-2234567',clean)
    def test_ordinal_and_written_dates(self):
        text='Admitted on 3rd March 2026 and discharged 13/05/2026.'
        clean=self.s.text(text,days=4)
        self.assertIn('7th March 2026',clean)
        self.assertIn('17/05/2026',clean)
    def test_labelled_and_prefixed_mrns(self):
        text='MRN: SNJ/26/064127; IPD No: DHH-2026-123456; Medical Record Number 064127'
        clean=self.s.text(text)
        self.assertNotIn('SNJ/26/064127',clean)
        self.assertNotIn('DHH-2026-123456',clean)
        self.assertNotIn('064127',clean)
    def test_plain_six_seven_digit_mrn_core(self):
        clean=self.s.text('Plain MRN 064127 and 1234567')
        self.assertNotIn('064127',clean)
        self.assertNotIn('1234567',clean)
if __name__=='__main__': unittest.main()
