import sys
import yaml
import glob
import os

def parse(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
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