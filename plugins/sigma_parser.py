import sys
import os
import yaml
import glob

def parse(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
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