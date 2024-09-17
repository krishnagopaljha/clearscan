import ast
import re
import os
import pefile

# ANSI color codes for TUI
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

# List of known dangerous imports and function calls for different languages
DANGEROUS_IMPORTS = {
    'python': ['os', 'subprocess', 'shutil', 'pickle', 'requests', 'socket', 'paramiko'],
    'c': ['system', 'popen', 'execvp', 'execve', 'fork', 'pipe'],
    'cpp': ['system', 'popen', 'execvp', 'execve', 'fork', 'pipe'],
    'go': ['os/exec', 'os', 'net/http', 'crypto/md5', 'crypto/sha1', 'crypto/sha256'],
    'rust': ['std::process::Command', 'std::fs::File', 'std::net::TcpStream', 'std::fs::read_to_string'],
    'bash': ['eval', 'exec', 'source', 'chmod', 'rm', 'wget', 'curl']
}

DANGEROUS_FUNCTIONS = {
    'python': ['exec', 'eval', 'os.system', 'subprocess.Popen', 'pickle.load', 'socket.socket'],
    'c': ['system', 'popen', 'execvp', 'execve', 'fork', 'pipe'],
    'cpp': ['system', 'popen', 'execvp', 'execve', 'fork', 'pipe'],
    'go': ['exec.Command', 'os.RemoveAll', 'os.OpenFile', 'net.Dial', 'crypto/md5.New', 'crypto/sha1.New'],
    'rust': ['std::process::Command::new', 'std::fs::File::open', 'std::net::TcpStream::connect'],
    'bash': ['eval', 'exec', 'source', 'chmod', 'rm', 'wget', 'curl']
}

def get_language_from_extension(file_path):
    """Detect the programming language based on the file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.py':
        return 'python'
    elif ext == '.c':
        return 'c'
    elif ext in ['.cpp', '.cxx', '.cc']:
        return 'cpp'
    elif ext == '.go':
        return 'go'
    elif ext == '.rs':
        return 'rust'
    elif ext == '.sh':
        return 'bash'
    else:
        return 'unknown'

def analyze_code(file_path):
    """Perform basic code analysis for source code."""
    lang = get_language_from_extension(file_path)
    if lang == 'unknown':
        print(RED + "Error: Unsupported file type." + RESET)
        return
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        print(CYAN + f"Detected language: {lang}" + RESET)
        print(CYAN + f"Analyzing {lang} code for suspicious patterns in {os.path.splitext(file_path)[1].lower()} file..." + RESET)

        # Check for dangerous imports
        found_imports = [imp for imp in DANGEROUS_IMPORTS.get(lang, []) if imp in content]
        if found_imports:
            print(YELLOW + "Warning: Use of potentially dangerous imports detected:" + RESET)
            for imp in found_imports:
                print(f"  Import: {imp}")
        else:
            print(GREEN + "No dangerous imports found." + RESET)

        # Check for dangerous function calls
        found_functions = [func for func in DANGEROUS_FUNCTIONS.get(lang, []) if re.search(r'\b' + re.escape(func) + r'\b', content)]
        if found_functions:
            print(YELLOW + "Warning: Dangerous function calls detected:" + RESET)
            for func in found_functions:
                print(f"  Function call: {func}")
        else:
            print(GREEN + "No dangerous function calls found." + RESET)

    except Exception as e:
        print(RED + f"Error analyzing code file: {str(e)}" + RESET)

def analyze_pe(file_path):
    """Analyze the PE headers for suspicious entries."""
    try:
        pe = pefile.PE(file_path)
        print(CYAN + "Analyzing PE Header..." + RESET)
        print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        
        # Check imported functions
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("Imports:")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"  DLL: {entry.dll.decode('utf-8')}")
                for func in entry.imports:
                    print(f"    {func.name.decode('utf-8')}")
    except Exception as e:
        print(RED + f"Error analyzing PE file: {str(e)}" + RESET)

def main():
    print(BOLD + "Advanced Static Code Analyzer" + RESET)
    print(BOLD + "="*30 + RESET)

    # User inputs
    file_path = input("Enter the path to the file: ").strip()
    if not os.path.isfile(file_path):
        print(RED + "Error: File path is incorrect." + RESET)
        return
    
    if file_path.lower().endswith(('.py', '.c', '.cpp', '.cxx', '.cc', '.go', '.rs', '.sh')):
        analyze_code(file_path)
    elif file_path.lower().endswith(('.exe', '.dll')):
        analyze_pe(file_path)
    else:
        print(RED + "Error: Unsupported file type." + RESET)
    
    print(GREEN + "Analysis complete." + RESET)

if __name__ == "__main__":
    main()
