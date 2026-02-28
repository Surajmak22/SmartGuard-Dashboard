import os
import sys

def check_imports(directory):
    errors = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "st." in content and "import streamlit" not in content:
                            errors.append(f"MISSING IMPORT: {path}")
                        if "pd." in content and "import pandas" not in content:
                            errors.append(f"MISSING IMPORT: {path}")
                        if "np." in content and "import numpy" not in content:
                            errors.append(f"MISSING IMPORT: {path}")
                        if "go." in content and "import plotly" not in content:
                            errors.append(f"MISSING IMPORT: {path}")
                except Exception as e:
                    errors.append(f"READ ERROR {path}: {e}")
    return errors

if __name__ == "__main__":
    src_dir = os.path.abspath("src")
    print(f"Checking directory: {src_dir}")
    issues = check_imports(src_dir)
    if issues:
        for issue in issues:
            print(issue)
    else:
        print("No critical missing imports found.")
