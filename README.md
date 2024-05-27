# Overview
return results known vulnerabilities by calling NVD NIST API

# CVE Fetcher

This script fetches CVE (Common Vulnerabilities and Exposures) data for specified CPE (Common Platform Enumeration) names from the NVD (National Vulnerability Database) and formats the data for further analysis. The script can optionally suppress standard output messages.

## Features

- Fetch CVE data from NVD using CPE names.
- Extract and format relevant CVE details, including CVSS scores and CWE IDs.
- Option to suppress stdout messages for cleaner output.

## Requirements

- Python 3.x
- `requests` library

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/cve-fetcher.git
    cd cve-fetcher
    ```

2. Install the required dependencies:
    ```bash
    pip install requests
    ```

3. Create a `config.ini` file in the root directory with the following structure:
4. The following is an example.
    ```ini
    [cpeName]
    cpe1 = your_cpe_name_1
    cpe2 = your_cpe_name_2
    # Add more CPE names as needed
    ```

## Usage

Run the script with optional arguments:
- --silent: Suppress stdout messages.

```bash
python cve_fetcher.py [--silent]
```

## Result
[sample_result.txt](https://github.com/myon-bioinformatics/nvd_nist_known_vulns/blob/main/sample_result.txt)

## License
This project is licensed under the MIT License.
