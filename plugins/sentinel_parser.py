import sys
import glob
import os
import yaml

def parse(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
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