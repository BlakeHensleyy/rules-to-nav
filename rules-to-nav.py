#!/usr/bin/env python3
# Derived from https://github.com/SigmaHQ/legacy-sigmatools/blob/master/tools/sigma/sigma2attack.py
import argparse
import importlib
import os
import sys
import json

def load_plugins(plugin_dir="plugins"):
    plugins = {}
    sys.path.insert(0, plugin_dir)  # Add plugins directory to the Python path
    for file in os.listdir(plugin_dir):
        if file.endswith(".py") and not file.startswith("__"):
            vendor_name = file[:-3].replace("_parser", "")  # Strip "_parser" suffix
            module_name = file[:-3]
            module = importlib.import_module(module_name)
            if hasattr(module, "parse"):
                plugins[vendor_name] = module.parse
    sys.path.pop(0)
    return plugins

def main():
    # Load parsing plugins first
    plugins = load_plugins()
    valid_rule_formats = list(plugins.keys())

    # Define argparse with dynamic choices for rule format
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--rules-directory", "-d", dest="rules_dir", default="rules", help="Directory to read rules from")
    parser.add_argument("--out-file", "-o", dest="out_file", default="heatmap.json", help="File to write the JSON layer to")
    parser.add_argument("--rule-format", "-f", dest="rule_format", default="sigma", choices=valid_rule_formats, help=f"Rule format to read. Options: {', '.join(valid_rule_formats)}")
    parser.add_argument("--input-csv", "-ic", dest="input_csv", default=None, help="CSV file to read Attack mapping and rules from. In the format of column 1 = Attack ID, column 2 (optional) = rule name")
    parser.add_argument("--no-comment", "-nc", dest="no_comment", action="store_true", help="Don't store rule names in comments")
    parser.add_argument("--status-start", "-s", dest="status_start", default="lowest_status", help="Check rule with minimum status")
    parser.add_argument("--status-end", "-se", dest="status_end", default="highest_status", help="Check rule with maximum status")
    parser.add_argument("--level-score", "-l", dest="level_score", action="store_true", help="ATT&CK technique score depends on rule level (severity).")
    parser.add_argument("--color-family", "-cf", dest="color_family", default="cool", help="Color family for the heatmap. Use for creating several, differentiated layers. Options are warm, cool, earthy, and neon")

    args = parser.parse_args()

    techniques_to_rules = {}
    score_to_rules = {}
    calc_score_severity = 0  # The calculated score by severity
    num_rules_used = 0
    num_rules_no_techniques = 0

    # Ensure the selected rule format is valid
    if args.rule_format not in valid_rule_formats:
        parser.error(f"Unsupported rule format: {args.rule_format}. Choose from: {', '.join(valid_rule_formats)}")

    # Call the selected parser function
    parser_function = plugins[args.rule_format]
    techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques = parser_function(
        techniques_to_rules, score_to_rules, calc_score_severity, num_rules_used, num_rules_no_techniques, args)

    scores = []
    for technique in techniques_to_rules:
        if args.level_score:
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
            "colors": color_family_dict[args.color_family],
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

color_family_dict = {
    "warm"   : ["#FFF5E1", "#FFA07A", "#FF4500"],  # From Light Peach to Bright OrangeRed
    "cool"   : ["#E0FFFF", "#00CED1", "#00008B"],  # From Light Cyan to DarkBlue
    "earthy" : ["#F5DEB3", "#C19A6B", "#8B4513"],  # From Wheat to DarkSaddleBrown
    "neon"   : ["#E0FF7F", "#FF69B4", "#39FF14"]  # From LightYellowGreen to Intense Neon Green
}

if __name__ == "__main__":
    main()
