import sys
import os
import glob
import toml

def parse(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
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