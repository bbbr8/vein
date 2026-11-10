import copy
import unittest
from vein_candidates import compare,coverage


class SchemaCandidates(unittest.TestCase):
    def packet(self):
        schema=lambda order:f'endian {order}\nroot packet\ntype packet {{\n level: u16\n}}\n'
        return {'candidates':[{'id':'be','source':schema('be')},{'id':'le','source':schema('le')}],
                'fixtures':[{'id':'valid','hex':'0102ff','checks':[{'pointer':'/fields/level/value','expected':258},{'pointer':'/fields/level/offset','expected':0},{'pointer':'/fields/level/size','expected':2}]},
                            {'id':'short','hex':'01','expect_error':True}]}

    def test_independent_byte_oracle_distinguishes_schemas(self):
        packet=self.packet();before=copy.deepcopy(packet);result=compare(packet)
        self.assertEqual(result['accepted'],['be']);self.assertEqual(packet,before)
        covered=result['candidates'][0]['fixtures'][0]['coverage']
        self.assertEqual((covered['decoded_leaf_bytes'],covered['undecoded_ranges']),(2,[[2,3]]))

    def test_swapped_fixture_is_a_counterexample(self):
        packet=self.packet();packet['fixtures'][0]['hex']='0201ff'
        self.assertEqual(compare(packet)['accepted'],['le'])

    def test_compile_errors_and_missing_pointer_are_feedback(self):
        packet=self.packet();packet['candidates'][0]['source']='broken'
        result=compare(packet);self.assertIn('compile_error',result['candidates'][0])
        packet=self.packet();packet['fixtures'][0]['checks'][0]['pointer']='/missing'
        self.assertEqual(compare(packet)['accepted'],[])

    def test_no_oracle_rejected_and_typed_equality(self):
        packet=self.packet();packet['fixtures'][0]['checks']=[]
        with self.assertRaises(ValueError):compare(packet)
        packet=self.packet();packet['fixtures'][0]['checks'][0]['expected']=True
        self.assertEqual(compare(packet)['accepted'],[])

    def test_overlapping_byte_ranges_and_unknown_tail(self):
        tree={'a':{'value':1,'offset':0,'size':2},'b':{'value':1,'offset':1,'size':2}}
        self.assertEqual(coverage(tree,4)['decoded_leaf_bytes'],3)
