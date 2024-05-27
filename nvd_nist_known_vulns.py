import argparse
import configparser
import requests
import json
import time

parser = argparse.ArgumentParser()
parser.add_argument(
    "--silent", help="Suppress stdout messages", action="store_true")
args = parser.parse_args()


def api_call(cpe_name):  # sourcery skip: inline-immediately-returned-variable
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}&resultsPerPage=999'
    uri = url.format(cpe_name=cpe_name)
    response = requests.get(uri)
    json_data = json.loads(response.text)
    return json_data

def format_cve_data(json_data):
    cve_data = {}
    vulnerabilities = json_data.get('vulnerabilities', [])
    for vuln in vulnerabilities:
        cve_id = vuln['cve']['id']
        current_description = vuln['cve']['descriptions'][0]['value']
        cwe_id = vuln['cve']['weaknesses'][0]['description'][0]['value']

        if 'cvssMetricV30' in vuln['cve']['metrics']:
            cvssv3_base_score = vuln['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
            cvssv3_vector_string = vuln['cve']['metrics']['cvssMetricV30'][0]['cvssData']['vectorString']

        if 'cvssMetricV31' in vuln['cve']['metrics']:
            cvssv3_base_score = vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
            cvssv3_vector_string = vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['vectorString']
        else:
            cvssv3_base_score = None
            cvssv3_vector_string = None

        if 'cvssMetricV2' in vuln['cve']['metrics']:
            cvssv2_base_score = vuln['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
            cvssv2_vector_string = vuln['cve']['metrics']['cvssMetricV2'][0]['cvssData']['vectorString']
        else:
            cvssv2_base_score = None
            cvssv2_vector_string =  None
        cve_data[cve_id]={cve_id, current_description, cwe_id, cvssv3_base_score, cvssv3_vector_string, cvssv2_base_score, cvssv2_vector_string}
    return cve_data

def arguments_all_print(*arguments):
    mapped_arguments = ",".join(map(str, arguments))
    print(mapped_arguments)
    return

def info_print(*arguments):
    if not args.silent:
        for a in arguments:
            print(a)
    return


def read_ini():  # sourcery skip: inline-immediately-returned-variable
    config = configparser.ConfigParser()
    config.read('config.ini')
    cpe_names = [config['cpeName'][key] for key in config['cpeName']]
    return cpe_names

def main():
    cpe_names = read_ini()
    for cpe_name in cpe_names:
        info_print("========", f"cpe_name: {cpe_name}", "========")
        json_data = api_call(cpe_name)
        info_print("Header: "+"cve_id,current_description,cwe_id,cvssv3_base_score,cvssv3_vector_string,cvssv2_base_score,cvssv2_vector_string")

        cve_data = format_cve_data(json_data)
        arguments_all_print(cve_data)
        time.sleep(15)

if __name__ == "__main__":
    main()
