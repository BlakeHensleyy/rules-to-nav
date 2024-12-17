import sys
import os
import csv

def parse(techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args):
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