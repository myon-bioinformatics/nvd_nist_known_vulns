import nvd_nist_known_vulns as nvd


def test_multiple_cpes_deduplicate_shared_ids_and_check_each_count():
    names=['cpe:2.3:a:example:a:1:*:*:*:*:*:*:*','cpe:2.3:a:example:b:1:*:*:*:*:*:*:*']
    rows=[]
    for name in names:
        rows += [{'kind':'cve','query':{'cpe_name':name},'id':ident} for ident in ('CVE-1','CVE-1','CVE-2')]
        rows.append({'kind':'query_complete','query':{'cpe_name':name},'cve_count':2})
    assert nvd.select_cpe_records(iter(rows),names)['cve_ids']==['CVE-1','CVE-2']
    rows[-1]['cve_count']=3
    assert nvd.select_cpe_records(rows,names)['mismatched_cpe_names']==[names[-1]]
