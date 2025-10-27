#!/usr/bin/env python3
"""
Script to extract module use cases from HawkEye3 modules
"""

import os
import re
from collections import defaultdict

def extract_usecases_from_file(filepath):
    """Extract useCases from a module file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Find the useCases line
        match = re.search(r"'useCases':\s*\[(.*?)\]", content, re.DOTALL)
        if match:
            usecases_str = match.group(1)
            # Extract individual use cases
            usecases = re.findall(r'"([^"]+)"', usecases_str)
            return usecases
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return []

def extract_module_name(filepath):
    """Extract module name from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Find the name in meta
        match = re.search(r"'name':\s*\"([^\"]+)\"", content)
        if match:
            return match.group(1)
    except:
        pass
    
    # Fallback to filename
    basename = os.path.basename(filepath)
    return basename.replace('hep_', '').replace('.py', '').replace('_', ' ').title()

def main():
    modules_dir = 'modules'
    
    # Dictionary to store modules by use case
    usecase_modules = defaultdict(list)
    
    # Get all module files
    module_files = [f for f in os.listdir(modules_dir) if f.startswith('hep_') and f.endswith('.py')]
    module_files.sort()
    
    print(f"Found {len(module_files)} modules")
    print("Extracting use cases...\n")
    
    for module_file in module_files:
        filepath = os.path.join(modules_dir, module_file)
        usecases = extract_usecases_from_file(filepath)
        module_name = extract_module_name(filepath)
        
        if usecases:
            for usecase in usecases:
                usecase_modules[usecase].append({
                    'file': module_file,
                    'name': module_name
                })
    
    # Print results
    print("=" * 80)
    print("MODULES BY USE CASE")
    print("=" * 80)
    print()
    
    for usecase in ['Footprint', 'Investigate', 'Passive']:
        modules = usecase_modules.get(usecase, [])
        print(f"\n{'=' * 80}")
        print(f"{usecase.upper()} - {len(modules)} modules")
        print(f"{'=' * 80}\n")
        
        for i, module in enumerate(modules, 1):
            print(f"{i:3}. {module['name']:<40} ({module['file']})")
    
    # Create markdown file
    with open('MODULE_USE_CASES.md', 'w', encoding='utf-8') as f:
        f.write("# HawkEye3 - Modules by Use Case\n\n")
        f.write("## Complete List of Modules for Each Use Case\n\n")
        
        for usecase in ['Footprint', 'Investigate', 'Passive']:
            modules = usecase_modules.get(usecase, [])
            f.write(f"\n## {usecase.upper()} ({len(modules)} modules)\n\n")
            f.write(f"**Purpose:** {get_usecase_description(usecase)}\n\n")
            
            for i, module in enumerate(modules, 1):
                f.write(f"{i}. **{module['name']}** (`{module['file']}`)\n")
    
    print(f"\n\nResults saved to MODULE_USE_CASES.md")

def get_usecase_description(usecase):
    descriptions = {
        'Footprint': 'Understand what information the target exposes to the Internet. Gain understanding about network perimeter, associated identities, and other information through web crawling and search engines.',
        'Investigate': 'Best for when you suspect the target to be malicious but need more information. Performs basic footprinting plus queries blacklists and threat intelligence sources.',
        'Passive': 'When you don\'t want the target to suspect they are being investigated. Gathers information without touching the target or their affiliates.'
    }
    return descriptions.get(usecase, '')

if __name__ == '__main__':
    main()
