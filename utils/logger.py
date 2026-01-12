"""
Logging utility for SQL Injection Toolkit
"""

import logging
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init()

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

def setup_logger(name='sql_toolkit', verbose=False, log_file=None):
    """Setup logger with custom formatting"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Custom format
    formatter = ColoredFormatter(
        fmt=f"{Fore.BLUE}[%(asctime)s]{Style.RESET_ALL} %(levelname)s: %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            fmt="[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def print_banner():
    """Print application banner"""
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    SQL INJECTION TOOLKIT                      ║
║                 Advanced Scanner & Exploiter                  ║
║                                                              ║
║                    Author: VSOP Project                       ║
║                    Version: 1.0.0                            ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def print_success(message):
    """Print success message"""
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message"""
    print(f"{Fore.RED}[!] {message}{Style.RESET_ALL}")

def print_warning(message):
    """Print warning message"""
    print(f"{Fore.YELLOW}[-] {message}{Style.RESET_ALL}")

def print_info(message):
    """Print info message"""
    print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")

def print_vulnerability(vuln):
    """Print vulnerability details"""
    print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.RED}[!] VULNERABILITY FOUND{Style.RESET_ALL}")
    print(f"{Fore.CYAN}    URL: {Style.RESET_ALL}{vuln['url']}")
    print(f"{Fore.CYAN}    Parameter: {Style.RESET_ALL}{vuln['parameter']}")
    print(f"{Fore.CYAN}    Method: {Style.RESET_ALL}{vuln['method']}")
    print(f"{Fore.CYAN}    Type: {Style.RESET_ALL}{vuln['type']}")
    print(f"{Fore.CYAN}    Payload: {Style.RESET_ALL}{vuln['payload']}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")

def print_exploitation_results(results):
    """Print exploitation results"""
    if not results:
        print_warning("No exploitation results available")
        return
    
    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] EXPLOITATION RESULTS{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}Database Type: {Style.RESET_ALL}{results.get('db_type', 'N/A')}")
    
    db_info = results.get('db_info', {})
    if db_info:
        print(f"{Fore.CYAN}Database Info:{Style.RESET_ALL}")
        for key, value in db_info.items():
            print(f"    {key}: {value}")
    
    tables = results.get('tables', [])
    if tables:
        print(f"{Fore.CYAN}Tables ({len(tables)}): {Style.RESET_ALL}")
        for table in tables[:10]:  # Show first 10 tables
            print(f"    - {table}")
        if len(tables) > 10:
            print(f"    ... and {len(tables) - 10} more")
    
    columns = results.get('columns', {})
    if columns:
        print(f"{Fore.CYAN}Columns:{Style.RESET_ALL}")
        for table, cols in list(columns.items())[:5]:  # Show first 5 tables
            print(f"    {table}: {', '.join(cols[:5])}")
    
    data = results.get('data', {})
    if data:
        print(f"{Fore.CYAN}Extracted Data:{Style.RESET_ALL}")
        for table, records in list(data.items())[:3]:  # Show first 3 tables
            print(f"    {table}:")
            for record in records[:3]:  # Show first 3 records
                print(f"      {record}")
    
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")
