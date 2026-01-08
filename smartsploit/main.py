#!/usr/bin/env python3
"""
SmartSploit Framework - Main Entry Point
Smart Contract Exploitation Framework with Metasploit-like architecture
"""

import os
import sys
import argparse
import logging
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colors
init(autoreset=True)

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=f'{Fore.CYAN}[%(asctime)s]{Style.RESET_ALL} %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )

def print_banner():
    """Print SmartSploit banner"""
    banner = f"""
{Fore.RED}
    ___                      _   ___       _       _ _   
   / __|_ __  __ _ _ _ _ _   _/ |_/ __| ___ | |___ _(_) |_ 
   \__ \ '  \/ _` | '_|  '_) |  \__ \|___|_ | / _ | |  _|
   |___/_|_|_\__,_|_|    |__/   |___/   |_/_\___\_|\__|
{Style.RESET_ALL}
{Fore.CYAN}        Smart Contract Exploitation Framework{Style.RESET_ALL}
{Fore.YELLOW}                 Version 2.1.0{Style.RESET_ALL}

{Fore.GREEN}[+] Smart contracts loaded and ready
[+] Type 'help' for available commands
[+] Type 'show exploits' to list exploit modules{Style.RESET_ALL}
    """
    print(banner)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SmartSploit Framework - Smart Contract Exploitation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Start interactive console
  %(prog)s --web                    # Start web interface  
  %(prog)s --console                # Start console interface
  %(prog)s --load-module exploit/reentrancy/classic
        """
    )
    
    parser.add_argument(
        '--web', 
        action='store_true',
        help='Start web interface instead of console'
    )
    
    parser.add_argument(
        '--console', 
        action='store_true',
        help='Start console interface (default)'
    )
    
    parser.add_argument(
        '--port', 
        type=int, 
        default=5000,
        help='Port for web interface (default: 5000)'
    )
    
    parser.add_argument(
        '--host', 
        default='0.0.0.0',
        help='Host for web interface (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--load-module', 
        metavar='MODULE',
        help='Load specific module at startup'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='SmartSploit Framework v2.1.0'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Print banner
    print_banner()
    
    try:
        if args.web:
            # Start web interface
            print(f"{Fore.GREEN}[+] Starting web interface...{Style.RESET_ALL}")
            from smartsploit.interfaces.web_ui.app import create_app
            
            app = create_app()
            print(f"{Fore.CYAN}[*] Web interface available at: http://{args.host}:{args.port}{Style.RESET_ALL}")
            app.run(host=args.host, port=args.port, debug=args.verbose)
            
        else:
            # Start console interface (default)
            print(f"{Fore.GREEN}[+] Starting console interface...{Style.RESET_ALL}")
            from smartsploit.interfaces.console import SmartSploitConsole
            
            console = SmartSploitConsole()
            
            # Load module if specified
            if args.load_module:
                print(f"{Fore.YELLOW}[*] Loading module: {args.load_module}{Style.RESET_ALL}")
                if console.framework.use_module(args.load_module):
                    print(f"{Fore.GREEN}[+] Module loaded successfully{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Failed to load module{Style.RESET_ALL}")
            
            # Start console loop
            console.cmdloop()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}[+] Goodbye!{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()