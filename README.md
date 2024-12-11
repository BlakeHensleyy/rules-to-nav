## Script Purpose

This script parses various threat detection rule formats and outputs a json file which can be used to generate a MTIRE ATT&CK heatmap.
Includes parsing for: 
- Sigma 
- Splunk 
- Elastic
- Sentinel
- Surricata
- csv

This can be used for security teams to assess the gaps that could exist between their threat detection tools.
This script can also be used to generate and compare different MITRE ATT&CK heatmaps for different vendors' entire public ruleset. Shortcomings between vendors can then more easily be identified.
### How to Use
Use one of the following commands to generate a heatmap.json file for a detection platform:

`python3 rules-to-navigator.py -f sigma -d rules/sigma -o sigma-heatmap.json`

`python3 rules-to-navigator.py -f sentinel -d rules/sentinel -o sentinel-heatmap.json`

`python3 rules-to-navigator.py -f splunk -d rules/splunk -o splunk-heatmap.json`

`python3 rules-to-navigator.py -f elastic -d rules/elastic -o elastic-heatmap.json`

`python3 rules-to-navigator.py -f suricata -d rules/suricata -o suricata-heatmap.json`

`python3 rules-to-navigator.py -f csv -ic rules/csv/unsupported-source.csv -o csv-heatmap.json`


Once you have the output .json file, it can be used here https://mitre-attack.github.io/attack-navigator/.
Click `Open Existing layer` then `Upload from local` and select the .json file.

**Other Examples**

`python3 rules-to-navigator.py -f elastic -d rules/elastic -o elastic-heatmap.json -cf neon`

`python3 rules-to-navigator.py -f sigma -d rules/sigma -o sigma-heatmap.json -s test -se stable`

`python3 rules-to-navigator.py -f suricata -d rules/suricata -o suricata-heatmap.json -nc True`
