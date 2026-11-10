import unittest
from vein_candidates import compare


class DecoderHardening(unittest.TestCase):
    def packet(self):
        return {'candidates':[{'id':'p','source':'root packet\ntype packet { level: u8 }'}],
                'fixtures':[{'id':'q','hex':'01ff','checks':[{'pointer':'/fields/level/value','expected':1}]}]}

    def test_limit_cannot_pass_negative_fixture(self):
        p=self.packet()
        p['candidates'][0]['source']='root packet\ntype packet { values: u8[10001] }'
        p['fixtures']=[{'id':'q','hex':'01'*10001,'expect_error':True}]
        r=compare(p)
        self.assertEqual(r['accepted'],[])
        self.assertEqual(r['candidates'][0]['fixtures'][0]['state'],'EVALUATION_LIMIT')

    def test_eof_or_fail_cannot_hide_limit(self):
        p=self.packet();p['max_items']=1
        p['candidates'][0]['source']='root packet\ntype packet { values: u8[] until eof_or_fail }'
        p['fixtures'][0]['checks']=[{'pointer':'/fields/values/items/0/value','expected':1}]
        self.assertEqual(compare(p)['accepted'],[])

    def test_explicit_full_coverage_rejects_unknown_tail(self):
        p=self.packet();p['fixtures'][0]['require_full_coverage']=True
        self.assertEqual(compare(p)['accepted'],[])
        p['fixtures'][0]['hex']='01'
        self.assertEqual(compare(p)['accepted'],['p'])

    def test_malformed_pointer_rejected_before_decoding(self):
        p=self.packet();p['fixtures'][0]['checks'][0]['pointer']='/bad~2'
        with self.assertRaises(ValueError):compare(p)

    def test_invalid_roots_and_budgets(self):
        for p in (None,[],True):
            with self.subTest(p=p),self.assertRaises(ValueError):compare(p)
        for n in (True,0,100001):
            p=self.packet();p['max_items']=n
            with self.subTest(n=n),self.assertRaises(ValueError):compare(p)

    def test_real_truncation_remains_expected_error(self):
        p=self.packet();p['fixtures']=[{'id':'q','hex':'','expect_error':True}]
        self.assertEqual(compare(p)['accepted'],['p'])

