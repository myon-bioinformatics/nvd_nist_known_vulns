import json
import statistics
import subprocess
import sys
import time
import types
import nvd_nist_known_vulns as nvd


def main():
    sha='36e14ad11301e7b49421eec2bee58c46136cebdc'
    old=types.ModuleType('baseline')
    exec(subprocess.check_output(['git','show',sha+':nvd_nist_known_vulns.py']),old.__dict__)
    names=[f'cpe:2.3:a:example:app{i}:1:*:*:*:*:*:*:*' for i in range(100)]
    rows=[]
    for name in names:
        rows.extend({'kind':'cve','query':{'cpe_name':name},'id':f'CVE-{i}'} for i in range(100))
        rows.append({'kind':'query_complete','query':{'cpe_name':name},'cve_count':100})
    expected=old.select_cpe_records(rows,names)
    samples={'baseline':[],'indexed':[]}
    for repeat in range(4):
        for k in (list(samples) if repeat%2 else list(reversed(samples))):
            fn=old.select_cpe_records if k=='baseline' else nvd.select_cpe_records
            start=time.perf_counter_ns()
            result=fn(rows,names)
            elapsed=time.perf_counter_ns()-start
            assert result==expected
            if repeat:samples[k].append(elapsed)
    print(json.dumps({'python':sys.version,'baseline_sha':sha,'cpes':100,'rows':len(rows),'samples_ns':samples,
                      'median_ns':{k:statistics.median(v) for k,v in samples.items()}},indent=2))


if __name__=='__main__':main()
