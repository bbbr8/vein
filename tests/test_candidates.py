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

    def test_competing_schemas_localize_the_disputed_byte(self):
        packet = self.packet()
        packet['candidates'] = [
            {'id': 'prefix', 'source': 'root p\ntype p { tag: u8 }'},
            {'id': 'longer', 'source': 'root p\ntype p { tag: u8\n next: u8 }'}]
        packet['fixtures'] = [{'id': 'same-tag', 'hex': '010203', 'checks': [
            {'pointer': '/fields/tag/value', 'expected': 1}]}]
        result = compare(packet)
        self.assertEqual(result['accepted'], ['prefix', 'longer'])
        row = result['coverage_comparison'][0]
        self.assertEqual((row['all_decoded_bytes'], row['disputed_bytes'], row['none_decoded_bytes']), (1, 1, 1))
        self.assertEqual(row['disputed_ranges'], [{'start': 1, 'end': 2, 'decoded_by': ['longer']}])

    def test_coverage_sweep_matches_bytewise_oracle(self):
        from random import Random
        from vein_candidates import compare_coverage
        rng = Random(302)
        for _ in range(40):
            n = rng.randrange(20)
            bits = [[rng.choice([True, False]) for i in range(n)] for j in range(4)]
            candidates = []
            for i, row in enumerate(bits):
                gaps = [[j, j + 1] for j, value in enumerate(row) if not value]
                candidates.append((str(i), {'undecoded_ranges': gaps, 'input_bytes': n}))
            result = compare_coverage(candidates)
            both = sum(all(col) for col in zip(*bits))
            neither = sum(not any(col) for col in zip(*bits))
            self.assertEqual((result['all_decoded_bytes'], result['none_decoded_bytes'],
                              result['disputed_bytes']), (both, neither, n - both - neither))
            for span in result['disputed_ranges']:
                for j in range(span['start'], span['end']):
                    self.assertEqual(span['decoded_by'], [str(i) for i in range(4) if bits[i][j]])

    def test_disputed_range_cap_keeps_complete_totals(self):
        from vein_candidates import compare_coverage
        size = 600
        entire = {'input_bytes': size, 'undecoded_ranges': []}
        alternate = {'input_bytes': size, 'undecoded_ranges': [[i, i+1] for i in range(0, size, 2)]}
        report = compare_coverage([('all', entire), ('alternating', alternate)])
        self.assertEqual(report['disputed_bytes'], 300)
        self.assertEqual(len(report['disputed_ranges']), 128)
        self.assertEqual(report['omitted_range_count'], 172)

class CoverageArithmetic(unittest.TestCase):
    def test_depth_and_pair_disagreement(self):
        from itertools import combinations
        from fractions import Fraction
        from vein_candidates import compare_coverage
        schemas = [[1,1,1,0], [1,1,0,0], [1,0,0,0]]
        def report(bits):
            return compare_coverage([(str(i), dict(input_bytes=len(row),
                        undecoded_ranges=[[j,j+1] for j,v in enumerate(row) if not v]))
                        for i,row in enumerate(bits)])
        actual = report(schemas)
        mismatches = sum(x != y for a,b in combinations(schemas, 2) for x,y in zip(a,b))
        self.assertEqual(actual['coverage_depth_bytes'], [1,1,1,1])
        self.assertEqual(actual['disagreeing_byte_pairs'], mismatches)
        self.assertEqual(actual['compared_byte_pairs'], 12)
        self.assertEqual(Fraction(actual['pair_disagreement_fraction']), Fraction(1,3))
        self.assertIsNone(report([[], []])['pair_disagreement_fraction'])
