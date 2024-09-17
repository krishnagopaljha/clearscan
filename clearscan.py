import os
import json

# Import utility functions from the 'test' package
from core.file_integrity import main as file_integrity_main
from core.malware_reverse_engeneering import main as malware_reverse_engineering_main
from core.static_code_analyzer import main as static_code_analyzer_main
from core.malware_heuristic_analysis import main as malware_heuristic_analysis_main

def logo():
    """Return the logo text."""
    return """
   ________                _____                
  / ____/ /__  ____ ______/ ___/_________ _____ 
 / /   / / _ \/ __ `/ ___/\__ \/ ___/ __ `/ __ \\
/ /___/ /  __/ /_/ / /   ___/ / /__/ /_/ / / / /
\____/_/\___/\__,_/_/   /____/\___/\__,_/_/ /_/ 
    """

def clear_screen():
    """Clear the terminal screen and set text color to green."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\033[92m", end='')  # Green color for terminal text

def print_centered(text):
    """Print text centered on the terminal screen."""
    terminal_size = os.get_terminal_size()
    terminal_width = terminal_size.columns
    lines = text.split('\n')
    for line in lines:
        print(line.center(terminal_width))

def print_menu():
    """Print the main menu."""
    menu_text = """
Select an option:
1. File Integrity Checker
2. Malware Reverse Engineering
3. Malware Heuristic Analysis
4. Static Code Analyzer
5. Exit
    """
    print_centered(menu_text)

def main():
    """Main interactive loop."""
    clear_screen()
    print_centered(logo())

    while True:
        print_menu()
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            file_integrity_main()
        elif choice == '2':
            malware_reverse_engineering_main()
        elif choice == '3':
            malware_heuristic_analysis_main()
        elif choice == '4':
            static_code_analyzer_main()
        elif choice == '5' or choice.lower() == 'exit':
            print_centered("Exiting...")
            break
        else:
            print_centered("Invalid choice, please select a number between 1 and 5.")

if __name__ == "__main__":
    main()
