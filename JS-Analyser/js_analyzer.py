#!/usr/bin/env python3
"""
JavaScript Security Analyzer
Analyzes JavaScript files from URLs for sensitive data, XSS vulnerabilities, and API endpoints.
"""

import sys
import json
import argparse
from typing import List, Dict, Any
from dataclasses import asdict
import colorama
from colorama import Fore, Style

# Import the enhanced analyzer
from analyzer import JavaScriptAnalyzer, AnalysisResult

colorama.init(autoreset=True)


class OutputFormatter:
    """Format analysis results for display"""
    
    @staticmethod
    def format_json(results: List[AnalysisResult]) -> str:
        """Format results as JSON"""
        return json.dumps([asdict(r) for r in results], indent=2)
    
    @staticmethod
    def format_text(results: List[AnalysisResult]) -> str:
        """Format results as readable text"""
        output = []
        
        for result in results:
            output.append(f"\n{'='*80}")
            output.append(f"{Fore.CYAN}URL: {result.url}{Style.RESET_ALL}")
            output.append(f"File Size: {result.file_size:,} bytes")
            output.append(f"Analysis Time: {result.analysis_timestamp}")
            output.append(f"{'='*80}\n")
            
            if result.errors:
                output.append(f"{Fore.RED}Errors:{Style.RESET_ALL}")
                for error in result.errors:
                    output.append(f"  ❌ {error}")
                output.append("")
            
            # API Keys
            if result.api_keys:
                output.append(f"{Fore.YELLOW}🔑 API Keys Found: {len(result.api_keys)}{Style.RESET_ALL}")
                for key in result.api_keys[:10]:  # Limit to 10
                    output.append(f"  • {key['type']} (Line {key['line']})")
                    output.append(f"    Match: {key['match'][:60]}...")
                if len(result.api_keys) > 10:
                    output.append(f"  ... and {len(result.api_keys) - 10} more")
                output.append("")
            
            # Credentials
            if result.credentials:
                output.append(f"{Fore.RED}🔐 Credentials Found: {len(result.credentials)}{Style.RESET_ALL}")
                for cred in result.credentials[:10]:
                    output.append(f"  • {cred['type']} (Line {cred['line']})")
                    output.append(f"    Match: {cred['match'][:60]}...")
                if len(result.credentials) > 10:
                    output.append(f"  ... and {len(result.credentials) - 10} more")
                output.append("")

            # Emails (New)
            if result.emails:
                output.append(f"{Fore.BLUE}📧 Emails Found: {len(result.emails)}{Style.RESET_ALL}")
                for email in result.emails[:10]:
                    output.append(f"  • {email['type']} (Line {email['line']})")
                    output.append(f"    Match: {email['match'][:60]}")
                if len(result.emails) > 10:
                    output.append(f"  ... and {len(result.emails) - 10} more")
                output.append("")
            
            # Comments
            if result.interesting_comments:
                output.append(f"{Fore.MAGENTA}💬 Interesting Comments: {len(result.interesting_comments)}{Style.RESET_ALL}")
                for comment in result.interesting_comments[:10]:
                    output.append(f"  • {comment['type']} (Line {comment['line']})")
                    output.append(f"    {comment['match'][:80]}")
                if len(result.interesting_comments) > 10:
                    output.append(f"  ... and {len(result.interesting_comments) - 10} more")
                output.append("")
            
            # XSS Vulnerabilities
            if result.xss_vulnerabilities:
                output.append(f"{Fore.RED}⚠️  XSS Vulnerabilities: {len(result.xss_vulnerabilities)}{Style.RESET_ALL}")
                for xss in result.xss_vulnerabilities:
                    severity = xss.get('severity', 'unknown')
                    severity_color = Fore.RED if severity == 'critical' else Fore.YELLOW if severity == 'high' else Fore.CYAN
                    output.append(f"  • {severity_color}[{severity.upper()}]{Style.RESET_ALL} {xss['type']} (Line {xss['line']})")
                    output.append(f"    {xss['match'][:80]}")
                output.append("")

            # XSS Functions (New)
            if result.xss_functions:
                output.append(f"{Fore.YELLOW}⚠️  Dangerous Functions: {len(result.xss_functions)}{Style.RESET_ALL}")
                for func in result.xss_functions[:10]:
                    output.append(f"  • {func['type']} (Line {func['line']})")
                if len(result.xss_functions) > 10:
                    output.append(f"  ... and {len(result.xss_functions) - 10} more")
                output.append("")
            
            # API Endpoints
            if result.api_endpoints:
                output.append(f"{Fore.GREEN}🌐 API Endpoints: {len(result.api_endpoints)}{Style.RESET_ALL}")
                for endpoint in result.api_endpoints[:20]:
                    output.append(f"  • [{endpoint['method']}] {endpoint['path']} (Line {endpoint['line']})")
                if len(result.api_endpoints) > 20:
                    output.append(f"  ... and {len(result.api_endpoints) - 20} more")
                output.append("")

            # Parameters (New)
            if result.parameters:
                output.append(f"{Fore.CYAN}📋 Parameters: {len(result.parameters)}{Style.RESET_ALL}")
                for param in result.parameters[:10]:
                    output.append(f"  • {param['match'][:60]} (Line {param['line']})")
                if len(result.parameters) > 10:
                    output.append(f"  ... and {len(result.parameters) - 10} more")
                output.append("")

            # Paths (New)
            if result.paths_directories:
                output.append(f"{Fore.CYAN}📁 Paths & Directories: {len(result.paths_directories)}{Style.RESET_ALL}")
                for path in result.paths_directories[:10]:
                    output.append(f"  • {path['match'][:60]} (Line {path['line']})")
                if len(result.paths_directories) > 10:
                    output.append(f"  ... and {len(result.paths_directories) - 10} more")
                output.append("")
            
            # Summary
            total_findings = (len(result.api_keys) + len(result.credentials) + 
                            len(result.xss_vulnerabilities) + len(result.emails))
            
            if total_findings == 0 and not result.api_endpoints:
                output.append(f"{Fore.GREEN}✓ No security issues detected{Style.RESET_ALL}\n")
            else:
                output.append(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
                output.append(f"  • API Keys: {len(result.api_keys)}")
                output.append(f"  • Credentials: {len(result.credentials)}")
                output.append(f"  • Emails: {len(result.emails)}")
                output.append(f"  • XSS Vulnerabilities: {len(result.xss_vulnerabilities)}")
                output.append(f"  • API Endpoints: {len(result.api_endpoints)}")
                output.append("")
        
        return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description='JavaScript Security Analyzer - Analyze JS files for sensitive data and vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com/app.js
  %(prog)s https://example.com/app.js https://example.com/lib.js
  %(prog)s -f urls.txt
  %(prog)s https://example.com/app.js -o results.json
        """
    )
    
    parser.add_argument('urls', nargs='*', help='URL(s) of JavaScript file(s) to analyze')
    parser.add_argument('-f', '--file', help='File containing URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output file path (JSON format)')
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--headers', help='Custom headers (JSON string)')
    parser.add_argument('--cookies', help='Custom cookies (JSON string)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    # Parse custom options
    custom_headers = None
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print(f"{Fore.RED}Error: Invalid JSON in --headers{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(1)

    cookies = None
    if args.cookies:
        try:
            cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            print(f"{Fore.RED}Error: Invalid JSON in --cookies{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(1)

    # Collect URLs
    urls = list(args.urls) if args.urls else []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found", file=sys.stderr)
            sys.exit(1)
    
    if not urls:
        parser.print_help()
        sys.exit(1)
    
    # Disable colors if requested
    if args.no_color:
        colorama.init(strip=True)
    
    # Analyze
    analyzer = JavaScriptAnalyzer()
    results = []
    
    print(f"{Fore.CYAN}Analyzing {len(urls)} JavaScript file(s)...{Style.RESET_ALL}\n")
    
    for url in urls:
        print(f"Fetching: {url}")
        result = analyzer.analyze(url, custom_headers=custom_headers, cookies=cookies, proxy=args.proxy)
        results.append(result)
    
    # Output results
    if args.json or args.output:
        output = OutputFormatter.format_json(results)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"\n{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")
        else:
            print(output)
    else:
        print(OutputFormatter.format_text(results))


if __name__ == '__main__':
    # Disable SSL warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()


