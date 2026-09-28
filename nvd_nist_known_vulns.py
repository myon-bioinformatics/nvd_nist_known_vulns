"""Dependency-free NVD CVE API 2.0 client."""
from __future__ import annotations
import argparse, configparser, json, os, sys, time
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD_CVE_API="https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE=2000
SCHEMA_VERSION="nvd-cve-summary/1"

def _request_json(url:str, *, api_key:str|None=None, timeout:float=30.0, retries:int=2)->dict[str,Any]:
    headers={"Accept":"application/json","User-Agent":"nvd_nist_known_vulns/stdlib"}
    if api_key: headers["apiKey"]=api_key
    for attempt in range(retries+1):
        try:
            with urlopen(Request(url,headers=headers),timeout=timeout) as response:
                return json.load(response)
        except HTTPError as exc:
            if exc.code==429 and attempt<retries:
                value=exc.headers.get("Retry-After")
                time.sleep(float(value) if value else 2.0**attempt); continue
            raise RuntimeError(f"NVD HTTP error {exc.code}: {exc.reason}") from exc
        except (URLError,TimeoutError) as exc:
            if attempt<retries: time.sleep(2.0**attempt); continue
            raise RuntimeError(f"NVD request failed: {exc}") from exc
    raise AssertionError("unreachable")

def api_call(cpe_name:str, *, start_index:int=0, results_per_page:int=DEFAULT_RESULTS_PER_PAGE, api_key:str|None=None, timeout:float=30.0)->dict[str,Any]:
    query=urlencode({"cpeName":cpe_name,"startIndex":start_index,"resultsPerPage":results_per_page})
    return _request_json(f"{NVD_CVE_API}?{query}",api_key=api_key,timeout=timeout)

def iter_cve_pages(cpe_name:str, *, api_key:str|None=None, timeout:float=30.0)->Iterable[dict[str,Any]]:
    start=0
    while True:
        page=api_call(cpe_name,start_index=start,api_key=api_key,timeout=timeout)
        yield page
        returned=len(page.get("vulnerabilities",[])); total=int(page.get("totalResults",returned))
        start+=returned
        if returned==0 or start>=total: return

def _description(cve):
    items=cve.get("descriptions",[])
    for item in items:
        if item.get("lang")=="en": return item.get("value")
    return items[0].get("value") if items else None

def _cwes(cve):
    out=[]
    for weakness in cve.get("weaknesses",[]):
        for item in weakness.get("description",[]):
            value=item.get("value")
            if value and value not in out: out.append(value)
    return out

def _metric(cve,names):
    metrics=cve.get("metrics",{})
    for name in names:
        if metrics.get(name):
            item=metrics[name][0]; data=item.get("cvssData",{})
            return {"version":data.get("version"),"base_score":data.get("baseScore"),"base_severity":data.get("baseSeverity") or item.get("baseSeverity"),"vector":data.get("vectorString")}
    return None

def format_cve_data(json_data):
    records={}
    for vulnerability in json_data.get("vulnerabilities",[]):
        cve=vulnerability.get("cve",{}); cve_id=cve.get("id")
        if not cve_id: continue
        records[cve_id]={"id":cve_id,"description":_description(cve),"cwe":_cwes(cve),"cvss_v4":_metric(cve,("cvssMetricV40",)),"cvss_v3":_metric(cve,("cvssMetricV31","cvssMetricV30")),"cvss_v2":_metric(cve,("cvssMetricV2",)),"published":cve.get("published"),"last_modified":cve.get("lastModified"),"source_identifier":cve.get("sourceIdentifier")}
    return records

def fetch_cves(cpe_name, *, api_key=None, timeout=30.0):
    records={}
    for page in iter_cve_pages(cpe_name,api_key=api_key,timeout=timeout): records.update(format_cve_data(page))
    return [records[k] for k in sorted(records)]

def read_ini(path="config.ini"):
    config=configparser.ConfigParser()
    if not config.read(path,encoding="utf-8"): raise FileNotFoundError(path)
    if "cpeName" not in config: raise ValueError(f"{path}: missing [cpeName] section")
    return [v.strip() for _,v in config["cpeName"].items() if v.strip()]

def main(argv=None):
    parser=argparse.ArgumentParser(description="Fetch known CVEs from NVD by CPE.")
    parser.add_argument("--silent",action="store_true"); parser.add_argument("--config",default="config.ini")
    parser.add_argument("--output"); parser.add_argument("--timeout",type=float,default=30.0)
    args=parser.parse_args(argv); stream=open(args.output,"w",encoding="utf-8") if args.output else sys.stdout
    try:
        for cpe in read_ini(args.config):
            if not args.silent: print(f"Fetching NVD CVEs for {cpe}",file=sys.stderr)
            for record in fetch_cves(cpe,api_key=os.environ.get("NVD_API_KEY"),timeout=args.timeout):
                print(json.dumps({"schema":SCHEMA_VERSION,"query":{"cpe_name":cpe},**record},ensure_ascii=False,sort_keys=True),file=stream)
    except (OSError,ValueError,RuntimeError) as exc:
        print(f"error: {exc}",file=sys.stderr); return 1
    finally:
        if args.output: stream.close()
    return 0
if __name__=="__main__": raise SystemExit(main())
