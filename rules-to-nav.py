#!/usr/bin/env python3
# Derived from https://github.com/SigmaHQ/legacy-sigmatools/blob/master/tools/sigma/sigma2attack.py
import argparse
import glob
import json
import os
import sys
import csv
import re
import yaml
import toml

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--rules-directory", "-d", dest="rules_dir", default="rules", help="Directory to read rules from")
    parser.add_argument("--out-file", "-o", dest="out_file", default="heatmap.json", help="File to write the JSON layer to")
    parser.add_argument("--rule-format", "-f", dest="rule_format", default="sigma", help="Rule format to read. Options: sigma, sentinel, splunk, elastic, suricata, and csv")
    parser.add_argument("--input-csv", "-ic", dest="input_csv", default=None, help="CSV file to read Attack mapping and rules from. In the format of column 1 = Attack ID, column 2 (optional) = rule name")
    parser.add_argument("--no-comment","-nc", dest="no_comment", action="store_true", help="Don't store rule names in comments")
    parser.add_argument("--status-start", "-s",dest="status_start", default="lowest_status", help="Check rule with minimun status")
    parser.add_argument("--status-end", "-se",dest="status_end", default="highest_status", help="Check rule with maximun status")
    parser.add_argument("--level-score", "-l",dest="level_score", action="store_true", help="ATT&CK technique score depends on rule level(severity).")
    parser.add_argument("--color-familly", "-cf",dest="color_familly", default="cool", help="Color familly for the heatmap. Use for creating several, differentiated layers. Options are warm, cool, earthy, and neon")

    args = parser.parse_args()

    techniques_to_rules = {}
    score_to_rules = {}
    calc_score_severity = 0 # The calculated score by severity
    num_rules_used = 0
    num_rules_no_techniques = 0

    # Dictionary of parsers for each rule format, for non-gross function calls
    parsers = {
        "sigma": sigma_parsing,
        "sentinel": sentinel_parsing,
        "splunk": splunk_parsing,
        "elastic": elastic_parsing,
        "suricata": suricata_parsing,
        "csv": csv_parsing
    }

    if args.rule_format in parsers:
        techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques = parsers[args.rule_format](
            techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args)
    else:
        sys.stderr.write(f"Unsupported rule format: {args.rule_format}\n")
        sys.exit(1)

    scores = []
    for technique in techniques_to_rules:
        if args.level_score == True:
            technique_score = sum(score_to_rules[technique])
        else:
            technique_score = len(techniques_to_rules[technique])
        entry = {
            "techniqueID": technique,
            "score": technique_score,
        }
        if not args.no_comment:
            entry["comment"] = "\n".join(techniques_to_rules[technique])

        scores.append(entry)

    output = {
        "name": f"{args.rule_format} rules heatmap",
        "versions": {
            "attack": "16",
            "navigator": "4.4.4",
            "layer": "4.2"
        },
        "domain": "enterprise-attack",
        "description": f"{args.rule_format.capitalize()} rules heatmap",
        "gradient": {
            "colors": color_familly_dict[args.color_familly],
            "maxValue": calc_score_severity,
            "minValue": 0
        },
        "techniques": scores,
    }

    with open(args.out_file, "w", encoding="UTF-8") as f:
        f.write(json.dumps(output, indent=4, ensure_ascii=False))
        print(f"[*] Layer file written in {args.out_file} ({str(num_rules_used)} rules)")
        if num_rules_no_techniques > 0:
            print(f"[-] Ignored {num_rules_no_techniques} rules without Mitre Technique")
        else:
            print(f"[*] No rules without Mitre Technique")

def sigma_parsing(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
    sigma_level_eq = {
        "informational" : 1,
        "low"           : 2,
        "medium"        : 3,
        "high"          : 4,
        "critical"      : 5
    }
    sigma_status_eq = {
        "unsupported"   : 1,
        "deprecated"    : 2,
        "experimental"  : 3,
        "test"          : 4,
        "stable"        : 5
    }
    mitre_var = "tags"
    status_var = "status"
    severity_var = "level"
    if args.status_start not in sigma_status_eq and args.status_start != 'lowest_status':
        sys.stderr.write(f"Invalid start status: {args.status_start}\n")
        sys.exit(1)
    if args.status_end not in sigma_status_eq and args.status_end != 'highest_status':
        sys.stderr.write(f"Invalid end status: {args.status_end}\n")
        sys.exit(1)
    status_start = min(sigma_status_eq.values()) if args.status_start == 'lowest_status' else sigma_status_eq[args.status_start]
    status_end = max(sigma_status_eq.values()) if args.status_end == 'highest_status' else sigma_status_eq[args.status_end]
    rule_files = glob.glob(os.path.join(args.rules_dir, "**/*.yml"), recursive=True)

    for rule_file in rule_files:
        with open(rule_file, encoding='utf-8') as f:
            docs = yaml.load_all(f, Loader=yaml.FullLoader)
            for rule in docs:
                if mitre_var not in rule:
                    sys.stderr.write(f"Ignoring rule {rule_file} no {mitre_var} field in rule\n")
                    continue
                status_name = rule.get(status_var, "experimental") # Default to experimental if no status is found
                status_nb = sigma_status_eq[status_name]

                if status_nb < status_start or status_nb > status_end: # Check if the status is in the range
                    sys.stderr.write(f"Ignoring rule {rule_file} filter status: {status_name}\n")
                    continue

                tags = rule[mitre_var]
                level = rule.get(severity_var, "medium") # Default to medium if no level is found
                mitre_tech_exists = False
                for tag in tags: # Loop through the technique field
                    if tag.lower().startswith("attack.t"):
                        mitre_tech_exists = True
                        technique_id = tag[len("attack."):].upper()
                        num_rules_used += 1
                        if technique_id not in techniques_to_rules: # Add the rule to the technique
                            techniques_to_rules[technique_id] = []
                            score_to_rules[technique_id] = []
                        techniques_to_rules[technique_id].append(os.path.basename(rule_file))
                        score_to_rules[technique_id].append(sigma_level_eq[level])
                        if args.level_score: # Calculate the score by level or by number of rules
                            calc_score_severity = max(calc_score_severity, sum(score_to_rules[technique_id]))
                        else:
                            calc_score_severity = max(calc_score_severity, len(techniques_to_rules[technique_id]))
                if not mitre_tech_exists:
                    sys.stderr.write(f"Ignoring rule {rule_file} no Techniques in {mitre_var}\n")
                    num_rules_no_techniques += 1

    return techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques

def sentinel_parsing(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
    sentinel_level_eq = {
        "Informational" : 1,
        "Low"           : 2,
        "Medium"        : 3,
        "High"          : 4
    }
    # Not really sure if there are other values or even if status is the status field for sentinel.
    sentinel_status_eq = {
        "Unsupported"   : 1, # DNE, added to fix script
        "Available"     : 2,
        "Production"    : 3  # DNE, added to fix script
    }
    # YAML file
    mitre_var = "relevantTechniques"
    status_var = "status"
    severity_var = "severity"
    if args.status_start not in sentinel_status_eq and args.status_start != 'lowest_status':
        sys.stderr.write(f"Invalid start status: {args.status_start}\n")
        sys.exit(1)
    if args.status_end not in sentinel_status_eq and args.status_end != 'highest_status':
        sys.stderr.write(f"Invalid end status: {args.status_end}\n")
        sys.exit(1)
    status_start = min(sentinel_status_eq.values()) if args.status_start == 'lowest_status' else sentinel_status_eq[args.status_start]
    status_end = max(sentinel_status_eq.values()) if args.status_end == 'highest_status' else sentinel_status_eq[args.status_end]
    rule_files = glob.glob(os.path.join(args.rules_dir, "**/*.yaml"), recursive=True)

    for rule_file in rule_files:
        with open(rule_file, encoding='utf-8') as f:
            docs = yaml.load_all(f, Loader=yaml.FullLoader)
            for rule in docs:
                if mitre_var not in rule:
                    sys.stderr.write(f"Ignoring rule {rule_file} no {mitre_var} field in rule\n")
                    continue
                status_name = rule.get(status_var, "Available") # Default to Available if no status is found
                status_nb = sentinel_status_eq[status_name]

                if status_nb < status_start or status_nb > status_end:
                    sys.stderr.write(f"Ignoring rule {rule_file} filter status: {status_name}\n")
                    continue

                relevantTechniques = rule[mitre_var]
                severity = rule[severity_var]
                mitre_tech_exists = False
                for relevantTechnique in relevantTechniques:
                    if relevantTechnique.startswith("T"):
                        mitre_tech_exists = True
                        technique_id = relevantTechnique
                        num_rules_used += 1
                        if technique_id not in techniques_to_rules:
                            techniques_to_rules[technique_id] = []
                            score_to_rules[technique_id] = []
                        techniques_to_rules[technique_id].append(os.path.basename(rule_file))
                        score_to_rules[technique_id].append(sentinel_level_eq[severity])
                        if args.level_score:
                            calc_score_severity = max(calc_score_severity, sum(score_to_rules[technique_id]))
                        else:
                            calc_score_severity = max(calc_score_severity, len(techniques_to_rules[technique_id]))
                if not mitre_tech_exists:
                    sys.stderr.write(f"Ignoring rule {rule_file} no Techniques in {mitre_var}\n")
                    num_rules_no_techniques += 1

    return techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques

def splunk_parsing(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
    splunk_status_eq = {
        "deprecated"    : 1,
        "experimental"  : 2,
        "production"    : 3
    }
    # YAML file
    # From the parent key of "tags"
    mitre_var = "mitre_attack_id"
    status_var = "status"
    severity_var = "impact"
    if args.status_start not in splunk_status_eq and args.status_start != 'lowest_status':
        sys.stderr.write(f"Invalid start status: {args.status_start}\n")
        sys.exit(1)
    if args.status_end not in splunk_status_eq and args.status_end != 'highest_status':
        sys.stderr.write(f"Invalid end status: {args.status_end}\n")
        sys.exit(1)
    status_start = min(splunk_status_eq.values()) if args.status_start == 'lowest_status' else splunk_status_eq[args.status_start]
    status_end = max(splunk_status_eq.values()) if args.status_end == 'highest_status' else splunk_status_eq[args.status_end]
    rule_files = glob.glob(os.path.join(args.rules_dir, "**/*.yml"), recursive=True)

    for rule_file in rule_files:
        with open(rule_file, encoding='utf-8') as f:
            docs = yaml.load_all(f, Loader=yaml.FullLoader)
            for rule in docs:
                tags = rule.get("tags", {})
                if mitre_var not in tags:
                    sys.stderr.write(f"Ignoring rule {rule_file} no {mitre_var} field in tags\n")
                    continue
                status_name = tags.get(status_var, "experimental")  # Default to experimental if no status is found
                status_nb = splunk_status_eq[status_name]

                if status_nb < status_start or status_nb > status_end:
                    sys.stderr.write(f"Ignoring rule {rule_file} filter status: {status_name}\n")
                    continue

                mitre_attack_id = tags.get(mitre_var, [])
                impact = tags.get(severity_var, None)
                mitre_tech_exists = False
                for mitre_id in mitre_attack_id:
                    if mitre_id.startswith("T"):
                        mitre_tech_exists = True
                        technique_id = mitre_id
                        num_rules_used += 1
                        if technique_id not in techniques_to_rules:
                            techniques_to_rules[technique_id] = []
                            score_to_rules[technique_id] = []
                        techniques_to_rules[technique_id].append(os.path.basename(rule_file))
                        score_to_rules[technique_id].append(impact/20) # Splunk impact is 1-100, so divide by 20 to get 1-5
                        if args.level_score:
                            calc_score_severity = max(calc_score_severity, sum(score_to_rules[technique_id]))
                        else:
                            calc_score_severity = max(calc_score_severity, len(techniques_to_rules[technique_id]))
                if not mitre_tech_exists:
                    sys.stderr.write(f"Ignoring rule {rule_file} no Techniques in {mitre_var}\n")
                    num_rules_no_techniques += 1

    return techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques

def elastic_parsing(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
    elastic_severity_eq = {
        "low"           : 1,
        "medium"        : 2,
        "high"          : 3,
        "critical"      : 4
    }
    elastic_maturity_eq = {
        "deprecated"    : 1,
        "development"   : 2,
        "experimental"  : 3,
        "beta"          : 4,
        "production"    : 5
    }
    # TOML file
    # From the parent key of rule.threat.technique
    mitre_var = "id"
    status_var = "maturity"
    severity_var = "severity"
    if args.status_start not in elastic_maturity_eq and args.status_start != 'lowest_status':
        sys.stderr.write(f"Invalid start status: {args.status_start}\n")
        sys.exit(1)
    if args.status_end not in elastic_maturity_eq and args.status_end != 'highest_status':
        sys.stderr.write(f"Invalid end status: {args.status_end}\n")
        sys.exit(1)
    status_start = min(elastic_maturity_eq.values()) if args.status_start == 'lowest_status' else elastic_maturity_eq[args.status_start]
    status_end = max(elastic_maturity_eq.values()) if args.status_end == 'highest_status' else elastic_maturity_eq[args.status_end]
    rule_files = glob.glob(os.path.join(args.rules_dir, "**/*.toml"), recursive=True)

    # TODO: get this to work with subtechniques... without adding 20+ lines of code.
    for rule_file in rule_files:
        with open(rule_file, encoding='utf-8') as f:
            rule = toml.load(f)

            mitre_tech_exists = False

            # Check if 'rule' -> 'threat' is a list and handle it accordingly
            if isinstance(rule['rule'].get('threat', []), list):
                for threat in rule['rule']['threat']:
                    if isinstance(threat, dict):
                        threat_techniques = threat.get('technique', [])
                        for technique in threat_techniques:
                            if isinstance(technique, dict):
                                technique_id = technique.get('id', None)
                                if technique_id and technique_id.startswith("T"):  # Ensure it's a valid technique ID
                                    status_name = rule.get('metadata', {}).get(status_var, "development") # set maturity to development by default
                                    status_nb = elastic_maturity_eq.get(status_name, 2)

                                    if status_nb < status_start or status_nb > status_end:
                                        sys.stderr.write(f"Ignoring rule {rule_file} due to maturity level: {status_name}\n")
                                        continue

                                    severity = rule['rule'].get(severity_var, None)
                                    mitre_tech_exists = True
                                    num_rules_used += 1
                                    if technique_id not in techniques_to_rules:
                                        techniques_to_rules[technique_id] = []
                                        score_to_rules[technique_id] = []
                                    techniques_to_rules[technique_id].append(os.path.basename(rule_file))
                                    score_to_rules[technique_id].append(elastic_severity_eq.get(severity, 0))
                                    if args.level_score:
                                        calc_score_severity = max(calc_score_severity, sum(score_to_rules[technique_id]))
                                    else:
                                        calc_score_severity = max(calc_score_severity, len(techniques_to_rules[technique_id]))
            if not mitre_tech_exists:
                sys.stderr.write(f"Ignoring rule {rule_file} due to no techniques found in {mitre_var}\n")
                num_rules_no_techniques += 1

    return techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques

def suricata_parsing(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
    suricata_confidence_eq = {
        "Low"        : 1,
        "Medium"     : 2,
        "High"       : 3
    }
    suricata_severity_eq = {
        "Informational" : 1,
        "Minor"         : 2,
        "Major"         : 3,
        "Critical"      : 4
    }
    # The value follows the format:  key + " " + value
    # TODO: Alligning with the mappings of the BETTER Schema, have several options for each var.
    mitre_var = "mitre_technique_id"
    status_var = "confidence"
    severity_var = "signature_severity"
    if args.status_start not in suricata_confidence_eq and args.status_start != 'lowest_status':
        sys.stderr.write(f"Invalid start status: {args.status_start}\n")
        sys.exit(1)
    if args.status_end not in suricata_confidence_eq and args.status_end != 'highest_status':
        sys.stderr.write(f"Invalid end status: {args.status_end}\n")
        sys.exit(1)
    status_start = min(suricata_confidence_eq.values()) if args.status_start == 'lowest_status' else suricata_confidence_eq[args.status_start]
    status_end = max(suricata_confidence_eq.values()) if args.status_end == 'highest_status' else suricata_confidence_eq[args.status_end]
    rule_files = glob.glob(os.path.join(args.rules_dir, "**/*.rules"), recursive=True)

    for rule_file in rule_files:
        with open(rule_file, encoding='utf-8') as f:
            for line in f:
                matches = {
                    "msg": re.search(r'msg:"(.*?)"', line),
                    "mitre": re.search(rf"{mitre_var} (\S+?)(?=,|\s)", line),
                    "status": re.search(rf"{status_var} (\S+?)(?=,|\s)", line),
                    "severity": re.search(rf"{severity_var} (\S+?)(?=,|\s)", line),
                }
                rule_name = matches["msg"].group(1) if matches["msg"] else None
                mitre_value = matches["mitre"].group(1) if matches["mitre"] else None
                status_value = matches["status"].group(1) if matches["status"] else "Medium" # Default to medium if no status is found
                severity_value = matches["severity"].group(1) if matches["severity"] else "Minor"
                mitre_tech_exists = False

                if not mitre_value:
                    sys.stderr.write(f"Ignoring rule {rule_name}: no {mitre_var} field in rule\n")
                    num_rules_no_techniques += 1
                    continue

                status_nb = suricata_confidence_eq[status_value]
                if not (status_start <= status_nb <= status_end):
                    sys.stderr.write(f"Ignoring rule {rule_name}: filter status: {status_value}\n")
                    continue

                if mitre_value.startswith("T"):
                    mitre_tech_exists = True
                    technique_id = mitre_value.upper()
                    num_rules_used += 1
                    if technique_id not in techniques_to_rules: # Add the rule to the technique
                        techniques_to_rules[technique_id] = []
                        score_to_rules[technique_id] = []
                    techniques_to_rules[technique_id].append(os.path.basename(rule_name))
                    score_to_rules[technique_id].append(suricata_severity_eq[severity_value])
                    if args.level_score: # Calculate the score by level or by number of rules
                        calc_score_severity = max(calc_score_severity, sum(score_to_rules[technique_id]))
                    else:
                        calc_score_severity = max(calc_score_severity, len(techniques_to_rules[technique_id]))
                if not mitre_tech_exists:
                    sys.stderr.write(f"Ignoring rule {rule_name} no Techniques in {mitre_var}\n")
                    num_rules_no_techniques += 1

    return techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques

def csv_parsing(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
    if not args.input_csv:
        sys.stderr.write("No CSV file provided.\n")
        sys.exit(1)
    if not os.path.exists(args.input_csv):
        sys.stderr.write(f"CSV file not found: {args.input_csv}\n")
        sys.exit(1)

    with open(args.input_csv, newline='') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)  # Skip the header row

        for row in reader:
            if len(row) < 2:
                print("Skipping row due to insufficient data.")
                continue
            technique_id = row[0]
            rule_name = row[1]

            if not technique_id or not technique_id.startswith("T"):
                sys.stderr.write(f"Ignoring rule {rule_name}: no valid technique ID\n")
                num_rules_no_techniques += 1
                continue

            num_rules_used += 1
            if technique_id not in techniques_to_rules:
                techniques_to_rules[technique_id] = []
                score_to_rules[technique_id] = []
            techniques_to_rules[technique_id].append(rule_name)
            score_to_rules[technique_id].append(1)  # Assign a default score of 1 for each rule
            calc_score_severity = max(calc_score_severity, len(techniques_to_rules[technique_id]))

    return techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques

color_familly_dict = {
    "warm"   : ["#FFF5E1", "#FFA07A", "#FF4500"],  # From Light Peach to Bright OrangeRed
    "cool"   : ["#E0FFFF", "#00CED1", "#00008B"],  # From Light Cyan to DarkBlue
    "earthy" : ["#F5DEB3", "#C19A6B", "#8B4513"],  # From Wheat to DarkSaddleBrown
    "neon"   : ["#E0FF7F", "#FF69B4", "#39FF14"]  # From LightYellowGreen to Intense Neon Green
}

if __name__ == "__main__":
    main()