"""Helper script to generate the client Python code from designer files automatically.
"""

import subprocess
import os
from pathlib import Path


def main():
    ui_files_dir = Path('pyside6_ui')
    output_files_dir = Path('app', 'client', 'ui')

    print("Generating client Python code from designer files")
    print("Input directory:", ui_files_dir)
    print("Output directory:", output_files_dir)
    print()

    for root, dirs, files in ui_files_dir.walk():
        print("Found pyside6-designer files:")
        for name in files:
            input_path = root / name
            print(f"> {input_path}")

        print()
        print("Which will be generated as:")
        for name in files:
            base, ext = os.path.splitext(name)
            output_path = output_files_dir / f'{base}.py'

            exists_or_new = "Exists" if output_path.exists() else "New"
            print(f"> {output_path} [{exists_or_new}]")

        print()
        proceed_prompt = input("Proceed? [Y/n]: ")

        if proceed_prompt.lower() == 'n' or proceed_prompt.lower() not in ['y', '']:
            print("Cancelled")
            return
        
        print("Running commands...")
        for name in files:
            input_path = root / name
            base, ext = os.path.splitext(name)

            output_path = output_files_dir / f'{base}.py'

            # pyside6-uic -o path.py path.ui
            cmd = ['pyside6-uic', '-o', str(output_path), str(input_path)]
            print(f"> {cmd}")

            subprocess.check_call(cmd)
        
        print("Completed!")


if __name__ == '__main__':
    main()
