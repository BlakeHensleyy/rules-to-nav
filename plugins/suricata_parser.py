import sys
import re
import os
import glob


def parse(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
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