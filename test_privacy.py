import unittest
from privacy import Sanitizer,evidence,band
from crypto import pseudonym,date_shift_days
import os

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
    def test_identity_key_map(self):
        result=self.s.value({'by_name':{'Example Person':'UHID-12345','Another Person':'UHID-54321'}})
        self.assertEqual(len(result['by_name']),2)
        self.assertNotIn('Example Person',str(result))
if __name__=='__main__': unittest.main()
