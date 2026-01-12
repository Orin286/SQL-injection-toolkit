#!/usr/bin/env python3
"""
SQL Injection Toolkit - Advanced SQL Injection Scanner and Exploiter
Author: VSOP Project
"""

import argparse
import sys
from core.scanner import SQLScanner
from core.exploiter import SQLExploiter
from core.mutator import PayloadMutator
from utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Toolkit')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--data', help='POST data in format "param1=value1&param2=value2"')
    parser.add_argument('--cookie', help='Cookie string')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--level', type=int, default=1, help='Scan level (1-5)')
    parser.add_argument('--risk', type=int, default=1, help='Risk level (1-3)')
    parser.add_argument('--mutate', action='store_true', help='Enable payload mutation')
    parser.add_argument('--output', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logger(verbose=args.verbose)
    
    try:
        # Initialize scanner
        scanner = SQLScanner(
            threads=args.threads,
            timeout=args.timeout,
            level=args.level,
            risk=args.risk
        )
        
        logger.info(f"[*] Starting SQL injection scan for: {args.url}")
        
        # Scan target
        vulnerabilities = scanner.scan_target(
            url=args.url,
            data=args.data,
            cookies=args.cookie
        )
        
        if vulnerabilities:
            logger.info(f"[+] Found {len(vulnerabilities)} SQL injection vulnerabilities")
            
            # Initialize exploiter
            exploiter = SQLExploiter()
            
            # Initialize mutator if enabled
            mutator = PayloadMutator() if args.mutate else None
            
            for vuln in vulnerabilities:
                logger.info(f"[*] Exploiting vulnerability: {vuln['parameter']}")
                
                # Exploit vulnerability
                result = exploiter.exploit(vuln, mutate=args.mutate, mutator=mutator)
                
                if result:
                    logger.info(f"[+] Successfully exploited: {vuln['parameter']}")
                    logger.info(f"[+] Database info: {result.get('db_info', 'N/A')}")
                    logger.info(f"[+] Current user: {result.get('current_user', 'N/A')}")
                    logger.info(f"[+] Database version: {result.get('version', 'N/A')}")
                    
                    # Display ready-to-use injection payloads
                    payloads = result.get('injection_payloads', [])
                    if payloads:
                        logger.info(f"[+] Generated {len(payloads)} ready-to-use injection payloads:")
                        logger.info("=" * 80)
                        logger.info("READY-TO-USE SQL INJECTION PAYLOADS:")
                        logger.info("=" * 80)
                        
                        for i, payload_info in enumerate(payloads, 1):
                            logger.info(f"\n[{i}] {payload_info['type']}")
                            logger.info(f"    Description: {payload_info['description']}")
                            logger.info(f"    Payload: {payload_info['payload']}")
                            logger.info(f"    URL: {payload_info['url']}")
                            if 'columns' in payload_info:
                                logger.info(f"    Columns: {', '.join(payload_info['columns'])}")
                        
                        logger.info("=" * 80)
                        logger.info("Copy and paste these URLs for direct exploitation!")
                        logger.info("=" * 80)
                        
                        # Save payloads to file if output specified
                        if args.output:
                            with open(args.output, 'a', encoding='utf-8') as f:
                                f.write(f"\n\n=== SQL INJECTION PAYLOADS for {vuln['parameter']} ===\n")
                                f.write(f"Target: {vuln['url']}\n")
                                f.write(f"Database Type: {result.get('db_type', 'Unknown')}\n")
                                f.write(f"Generated: {len(payloads)} payloads\n\n")
                                
                                for i, payload_info in enumerate(payloads, 1):
                                    f.write(f"[{i}] {payload_info['type']}\n")
                                    f.write(f"    Description: {payload_info['description']}\n")
                                    f.write(f"    Payload: {payload_info['payload']}\n")
                                    f.write(f"    URL: {payload_info['url']}\n")
                                    if 'columns' in payload_info:
                                        f.write(f"    Columns: {', '.join(payload_info['columns'])}\n")
                                    f.write("\n")
                        
                        logger.info(f"Payloads saved to: {args.output}" if args.output else "")
                else:
                    logger.warning(f"[-] Failed to exploit: {vuln['parameter']}")
        else:
            logger.info("[-] No SQL injection vulnerabilities found")
            
    except KeyboardInterrupt:
        logger.info("[*] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
