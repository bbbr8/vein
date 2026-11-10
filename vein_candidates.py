"""Check proposed Vein schemas against bounded byte fixtures and declared oracles.

No model is called. Use this executable feedback surface for model-written schema
candidates. Every input is hash-bound; decoded-leaf byte coverage stays explicit.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import vein


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def pointer(value,path):
    if not isinstance(path,str) or not path.startswith('/'):
        raise ValueError('An absolute JSON pointer is required')
    for key in path.split('/')[1:]:
        if re.search(r'~(?![01])',key):raise ValueError('Invalid pointer escape')
        key=key.replace('~1','/').replace('~0','~')
        if isinstance(value,list):
            if not key.isdigit() or len(key)>1 and key.startswith('0'):raise ValueError('Invalid array index')
            value=value[int(key)]
        else:value=value[key]
    return value


def coverage(tree,size):
    intervals=[]
    def walk(node):
        if isinstance(node,dict):
            if 'value' in node and type(node.get('offset')) is int and type(node.get('size')) is int:
                lo,hi=max(0,node['offset']),min(size,node['offset']+node['size'])
                if lo<hi:intervals.append((lo,hi))
            for value in node.values():walk(value)
        elif isinstance(node,list):
            for value in node:walk(value)
    walk(tree);merged=[]
    for lo,hi in sorted(intervals):
        if merged and lo<=merged[-1][1]:merged[-1][1]=max(hi,merged[-1][1])
        else:merged.append([lo,hi])
    gaps=[];end=0
    for lo,hi in merged:
        if lo>end:gaps.append([end,lo])
        end=hi
    if end<size:gaps.append([end,size])
    return {'input_bytes':size,'decoded_leaf_bytes':sum(hi-lo for lo,hi in merged),
            'undecoded_ranges':gaps,'scope':'bytes touched by decoded leaves; bit-level completeness is separate'}


def compare(packet):
    if not isinstance(packet,dict):raise ValueError('Candidate packet must be an object')
    max_items=packet.get('max_items',10000)
    if type(max_items) is not int or not 1<=max_items<=100000:raise ValueError('max_items must be 1..100000')
    candidates=packet.get('candidates');fixtures=packet.get('fixtures')
    if not isinstance(candidates,list) or not 1<=len(candidates)<=16:raise ValueError('Supply 1..16 schema candidates')
    if not isinstance(fixtures,list) or not 1<=len(fixtures)<=64:raise ValueError('Supply 1..64 fixtures')
    prepared=[];seen=set();total=0
    for f in fixtures:
        if not isinstance(f,dict) or not isinstance(f.get('id'),str) or not f['id'] or f['id'] in seen:raise ValueError('Fixture IDs must be unique text')
        seen.add(f['id'])
        if not isinstance(f.get('hex'),str) or len(f['hex'])>131072:raise ValueError('Fixture hex exceeds 64 KiB')
        data=bytes.fromhex(f['hex']);total+=len(data)
        if total>1048576:raise ValueError('Total fixture bytes exceed 1 MiB')
        checks=f.get('checks',[]);reject=f.get('expect_error',False)
        if type(f.get('require_full_coverage',False)) is not bool:raise ValueError('require_full_coverage must be boolean')
        if type(reject) is not bool or not isinstance(checks,list) or len(checks)>128 or bool(checks)==reject:raise ValueError('Each fixture needs checks or expect_error:true')
        for check in checks:
            if not isinstance(check,dict) or set(check)!={'pointer','expected'}:raise ValueError('Each check needs pointer and expected')
            if not isinstance(check['pointer'],str) or not check['pointer'].startswith('/'):
                raise ValueError('Each check needs an absolute JSON pointer')
            if re.search(r'~(?![01])',check['pointer']):raise ValueError('Invalid pointer escape')
            canonical(check)
        prepared.append((f,data,hashlib.sha256(data).hexdigest()))
    results=[];seen=set()
    for candidate in candidates:
        if not isinstance(candidate,dict) or not isinstance(candidate.get('id'),str) or not candidate['id'] or candidate['id'] in seen:raise ValueError('Candidate IDs must be unique text')
        seen.add(candidate['id']);source=candidate.get('source')
        if not isinstance(source,str) or len(source.encode())>65536:raise ValueError('Schema source exceeds 64 KiB')
        row={'id':candidate['id'],'schema_sha256':hashlib.sha256(source.encode()).hexdigest(),'passed':False,'fixtures':[]}
        try:schema=vein.compile(source)
        except vein.VeinError as exc:
            row['compile_error']=str(exc);results.append(row);continue
        for fixture,data,sha in prepared:
            item={'id':fixture['id'],'input_sha256':sha,'passed':False}
            try:
                tree=json.loads(vein.to_json(schema.parse(data,max_items=max_items)))
                def limited(node):
                    if isinstance(node,dict):
                        stopped=node.get('stopped')
                        if isinstance(stopped,dict) and str(stopped.get('reason','')).startswith('max_items '):return True
                        return any(limited(v) for v in node.values())
                    return isinstance(node,list) and any(limited(v) for v in node)
                if limited(tree):
                    item.update(state='EVALUATION_LIMIT',diagnostic='decoded array stopped at max_items')
                    row['fixtures'].append(item);continue
                checks=[]
                for check in fixture.get('checks',[]):
                    try:
                        actual=pointer(tree,check['pointer']);ok=canonical(actual)==canonical(check['expected'])
                        checks.append({**check,'actual':actual,'passed':ok})
                    except (ValueError,KeyError,IndexError,TypeError):
                        checks.append({**check,'passed':False,'diagnostic':'decoded pointer unavailable'})
                covered=coverage(tree,len(data))
                coverage_ok=not fixture.get('require_full_coverage',False) or not covered['undecoded_ranges']
                item.update(state='DECODED',checks=checks,coverage=covered,coverage_passed=coverage_ok,
                            passed=not fixture.get('expect_error',False) and coverage_ok and all(c['passed'] for c in checks))
            except vein.ResourceLimitError as exc:
                item.update(state='EVALUATION_LIMIT',parse_error=str(exc))
            except vein.ParseError as exc:
                item.update(state='DATA_REJECTED',passed=fixture.get('expect_error',False),parse_error=str(exc))
            row['fixtures'].append(item)
        row['passed']=all(f['passed'] for f in row['fixtures'])
        results.append(row)
    accepted=[r['id'] for r in results if r['passed']]
    # Schema differences outside supplied checks remain open, even when outcomes agree.
    return {'schema':'vein.candidates.v1','state':'MATCHES_FIXTURES' if accepted else 'NO_MATCH',
            'accepted':accepted,'candidates':results,'max_items':max_items,'fixture_sha256':hashlib.sha256(canonical(fixtures).encode()).hexdigest(),
            'scope':'declared finite fixtures, expected values and decoded-byte coverage; no universal schema correctness'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('packet',type=Path);a=parser.parse_args()
    try:result=compare(json.loads(a.packet.read_text()))
    except (ValueError,KeyError,TypeError,OSError) as exc:parser.exit(2,str(exc)+'\n')
    print(json.dumps(result,indent=2));return 0 if result['accepted'] else 1


if __name__=='__main__':raise SystemExit(main())
