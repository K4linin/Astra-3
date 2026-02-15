#!/usr/bin/env python3
"""Analyze crash files and generate report"""

import os
import json
from collections import Counter
from pathlib import Path

def analyze_crashes(target: str):
    crashes_dir = Path(f"fuzz/crashes/{target}")
    
    if not crashes_dir.exists():
        print(f"No crashes directory for target: {target}")
        return
    
    files = list(crashes_dir.glob("*.crash"))
    print(f"=" * 60)
    print(f"CRASH ANALYSIS FOR: {target}")
    print(f"=" * 60)
    print(f"Total crash files: {len(files)}")
    
    if not files:
        return
    
    # Collect statistics
    crash_types = Counter()
    severities = Counter()
    false_positives = 0
    stack_traces = {}
    
    for crash_file in files:
        try:
            with open(crash_file) as f:
                data = json.load(f)
            
            crash_type = data.get('crash_type', 'Unknown')
            severity = data.get('severity', 'unknown')
            
            crash_types[crash_type] += 1
            severities[severity] += 1
            
            if data.get('is_false_positive'):
                false_positives += 1
            
            # Store first example of each crash type
            if crash_type not in stack_traces:
                stack_traces[crash_type] = {
                    'file': crash_file.name,
                    'stack_trace': data.get('stack_trace', ''),
                    'input_hex': data.get('input_hex', '')
                }
                
        except Exception as e:
            print(f"Error reading {crash_file}: {e}")
    
    # Print summary
    print(f"\n{'CRASH TYPES':=^60}")
    for crash_type, count in crash_types.most_common():
        print(f"  {crash_type}: {count}")
    
    print(f"\n{'SEVERITY DISTRIBUTION':=^60}")
    for severity, count in severities.most_common():
        print(f"  {severity}: {count}")
    
    print(f"\n{'SUMMARY':=^60}")
    print(f"  False positives: {false_positives}")
    print(f"  Real crashes: {len(files) - false_positives}")
    
    # Print example stack traces
    print(f"\n{'EXAMPLE STACK TRACES':=^60}")
    for crash_type, info in list(stack_traces.items())[:3]:
        print(f"\n--- {crash_type} (from {info['file']}) ---")
        print(f"Input (hex): {info['input_hex'][:100]}...")
        print(f"\nStack trace:")
        # Print last 10 lines of stack trace
        lines = info['stack_trace'].split('\n')
        for line in lines[-15:]:
            print(f"  {line}")

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else 'img2pdf_convert'
    analyze_crashes(target)