"""
SmartSploit Console Interface
Metasploit-like command line interface for smart contract exploitation
"""

import cmd
import os
import sys
import json
import time
from typing import Dict, List, Optional, Any
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    # Fallback color constants
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        RESET = '\033[0m'
    
    class Style:
        RESET_ALL = '\033[0m'

try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

# Import framework components
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from smartsploit.core.framework import get_framework, ExploitResult

class SmartSploitConsole(cmd.Cmd):
    """
    Main console interface for SmartSploit Framework
    Provides Metasploit-like command interface
    """
    
    def __init__(self):
        super().__init__()
        self.framework = get_framework()
        
        # Console configuration
        self.intro = self._get_banner()
        self.prompt = f"{Fore.RED}smartsploit{Style.RESET_ALL} > "
        
        # Command history
        self.history_file = os.path.expanduser("~/.smartsploit_history")
        if HAS_READLINE:
            self._load_history()
            readline.set_completer_delims(" \t\n;")
            readline.parse_and_bind("tab: complete")
        
    def _get_banner(self) -> str:
        """Get startup banner"""
        banner = f"""
{Fore.RED}
    ___                      _   ___       _       _ _   
   / __|_ __  __ _ _ _ _ _   _/ |_/ __| ___ | |___ _(_) |_ 
   \__ \ '  \/ _` | '_|  '_) |  \__ \|___|_ | / _ | |  _|
   |___/_|_|_\__,_|_|    |__/   |___/   |_/_\___\_|\__|
{Style.RESET_ALL}
{Fore.CYAN}        Smart Contract Exploitation Framework{Style.RESET_ALL}
{Fore.YELLOW}                 Version {self.framework.version}{Style.RESET_ALL}

{Fore.GREEN}[+] Smart contracts loaded and ready
[+] Type 'help' for available commands
[+] Type 'show exploits' to list exploit modules{Style.RESET_ALL}
        """
        return banner
        
    def _load_history(self):
        """Load command history"""
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass
            
    def _save_history(self):
        """Save command history"""
        if HAS_READLINE:
            try:
                readline.write_history_file(self.history_file)
            except:
                pass
            
    def cmdloop(self, intro=None):
        """Enhanced command loop with history saving"""
        try:
            super().cmdloop(intro)
        finally:
            self._save_history()
            
    def emptyline(self):
        """Handle empty line input"""
        pass
        
    def default(self, line):
        """Handle unrecognized commands"""
        print(f"{Fore.RED}[-] Unknown command: {line}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Type 'help' for available commands{Style.RESET_ALL}")
        
    def do_use(self, args):
        """
        Use a specific module
        Usage: use <module_type>/<module_name>
        Example: use exploit/reentrancy/classic
        """
        if not args:
            print(f"{Fore.RED}[-] Module path required{Style.RESET_ALL}")
            print("Usage: use <module_path>")
            print("Examples:")
            print("  use exploit/reentrancy/classic")
            print("  use auxiliary/scanner/vulnerability")
            return
            
        # Map common module paths
        module_map = {
            "exploit/reentrancy/classic": "exploit/reentrancy/classic",
            "exploit/overflow/integer": "exploit/overflow/integer", 
            "exploit/access_control/tx_origin": "exploit/access_control/tx_origin",
            "auxiliary/scanner/vulnerability": "auxiliary/scanner/vulnerability"
        }
        
        module_path = module_map.get(args, args)
        
        if self.framework.use_module(module_path):
            self.prompt = f"{Fore.RED}smartsploit{Style.RESET_ALL} {Fore.BLUE}{args}{Style.RESET_ALL} > "
            print(f"{Fore.GREEN}[+] Using module: {args}{Style.RESET_ALL}")
            
            # Show module info
            info = self.framework.show_info()
            if info:
                print(f"\nModule: {info['name']}")
                print(f"Author: {info['author']}")
                print(f"Description: {info['description']}")
        else:
            print(f"{Fore.RED}[-] Failed to load module: {args}{Style.RESET_ALL}")
            print("Available modules:")
            modules = self.framework.module_manager.list_modules()
            for module in modules[:5]:  # Show first 5
                print(f"  {module}")
            
    def complete_use(self, text, line, begidx, endidx):
        """Tab completion for use command"""
        if not HAS_READLINE:
            return []
        modules = [
            "exploit/reentrancy/classic",
            "exploit/overflow/integer",
            "exploit/access_control/tx_origin", 
            "auxiliary/scanner/vulnerability"
        ]
        return [m for m in modules if m.startswith(text)]
        
    def do_back(self, args):
        """
        Return to main context
        Usage: back
        """
        self.framework.current_module = None
        self.prompt = f"{Fore.RED}smartsploit{Style.RESET_ALL} > "
        print(f"{Fore.GREEN}[+] Returned to main context{Style.RESET_ALL}")
        
    def do_info(self, args):
        """
        Show information about current module
        Usage: info
        """
        info = self.framework.show_info()
        if not info:
            print(f"{Fore.RED}[-] No module selected{Style.RESET_ALL}")
            print("Use 'use <module>' to select a module first")
            return
            
        print(f"\n{Fore.CYAN}Module Information:{Style.RESET_ALL}")
        print(f"{'='*50}")
        print(f"  Name: {info['name']}")
        print(f"  Description: {info['description']}")
        print(f"  Author: {info['author']}")
        print(f"  Severity: {info['severity']}")
        
        if info['references']:
            print(f"  References:")
            for ref in info['references']:
                print(f"    - {ref}")
                
        if info['targets']:
            print(f"  Targets:")
            for target in info['targets']:
                print(f"    - {target}")
                
    def do_show(self, args):
        """
        Show various information
        Usage: show <type>
        Types: exploits, auxiliary, payloads, options, sessions, targets
        """
        if not args:
            print("Usage: show <type>")
            print("Types: exploits, auxiliary, payloads, options, sessions, targets")
            return
            
        args = args.lower()
        
        if args == "exploits":
            self._show_modules("exploit")
        elif args == "auxiliary":
            self._show_modules("auxiliary")
        elif args == "payloads":
            self._show_modules("payload")
        elif args == "options":
            self._show_options()
        elif args == "sessions":
            self._show_sessions()
        elif args == "targets":
            self._show_targets()
        else:
            print(f"{Fore.RED}[-] Unknown show type: {args}{Style.RESET_ALL}")
            
    def complete_show(self, text, line, begidx, endidx):
        """Tab completion for show command"""
        if not HAS_READLINE:
            return []
        options = ["exploits", "auxiliary", "payloads", "options", "sessions", "targets"]
        return [opt for opt in options if opt.startswith(text)]
        
    def _show_modules(self, module_type):
        """Show modules of specific type"""
        modules = self.framework.module_manager.list_modules(module_type)
        if not modules:
            print(f"{Fore.YELLOW}[-] No {module_type} modules loaded{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}{module_type.title()} Modules:{Style.RESET_ALL}")
        print(f"{'='*60}")
        
        for i, module in enumerate(modules, 1):
            print(f"{i:3}. {module}")
            
        print(f"\nTotal: {len(modules)} modules")
        print(f"\nUse 'use <module_path>' to select a module")
        
    def _show_options(self):
        """Show current module options"""
        options = self.framework.show_options()
        if not options:
            print(f"{Fore.YELLOW}[-] No options available{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}Module Options:{Style.RESET_ALL}")
        print(f"{'Name':<20} {'Current Setting':<20} {'Required':<10} {'Description'}")
        print("=" * 70)
        
        # Show current module options first
        if self.framework.current_module:
            for key, value in self.framework.current_module.options.items():
                required = "yes" if key in self.framework.current_module.required_options else "no"
                value_str = str(value) if value is not None else ""
                print(f"{key:<20} {value_str:<20} {required:<10}")
                
        # Show global options
        print(f"\n{Fore.CYAN}Global Options:{Style.RESET_ALL}")
        for key, value in self.framework.global_options.items():
            print(f"{key:<20} {str(value):<20} {'no':<10}")
            
    def _show_sessions(self):
        """Show active sessions"""
        sessions = self.framework.session_manager.list_active_sessions()
        if not sessions:
            print(f"{Fore.YELLOW}[-] No active sessions{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}Active Sessions:{Style.RESET_ALL}")
        print(f"{'ID':<10} {'Target':<42} {'Exploit':<30} {'Status'}")
        print("=" * 90)
        
        for session in sessions:
            session_id = session['id']
            target = session['target']
            exploit = session['exploit']
            status = session['status']
            print(f"{session_id:<10} {target.address:<42} {exploit:<30} {status}")
            
    def _show_targets(self):
        """Show discovered targets"""
        print(f"{Fore.YELLOW}[*] Target discovery feature coming soon{Style.RESET_ALL}")
        print("This will show automatically discovered vulnerable contracts")
        
    def do_set(self, args):
        """
        Set option value
        Usage: set <option> <value>
        Example: set TARGET 0x1234567890123456789012345678901234567890
        """
        if not args:
            print("Usage: set <option> <value>")
            print("Examples:")
            print("  set TARGET 0x1234567890123456789012345678901234567890")
            print("  set AMOUNT 1.5")
            print("  set NETWORK mainnet")
            return
            
        parts = args.split(' ', 1)
        if len(parts) != 2:
            print("Usage: set <option> <value>")
            return
            
        key, value = parts
        key = key.upper()
        
        # Try to convert value to appropriate type
        if value.lower() in ['true', 'false']:
            value = value.lower() == 'true'
        elif value.isdigit():
            value = int(value)
        elif value.replace('.', '').replace('-', '').isdigit():
            value = float(value)
            
        self.framework.set_option(key, value)
        print(f"{Fore.GREEN}[+] {key} => {value}{Style.RESET_ALL}")
        
    def complete_set(self, text, line, begidx, endidx):
        """Tab completion for set command"""
        if not HAS_READLINE:
            return []
        options = list(self.framework.show_options().keys())
        return [opt for opt in options if opt.startswith(text.upper())]
        
    def do_unset(self, args):
        """
        Unset option value
        Usage: unset <option>
        """
        if not args:
            print("Usage: unset <option>")
            return
            
        key = args.upper()
        self.framework.set_option(key, None)
        print(f"{Fore.GREEN}[+] Unset {key}{Style.RESET_ALL}")
        
    def do_run(self, args):
        """
        Run current module
        Usage: run
        Alias: exploit
        """
        if not self.framework.current_module:
            print(f"{Fore.RED}[-] No module selected{Style.RESET_ALL}")
            print("Use 'use <module>' to select a module first")
            return
            
        print(f"{Fore.YELLOW}[*] Running module...{Style.RESET_ALL}")
        start_time = time.time()
        
        result = self.framework.run_current_module()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Display results
        self._display_result(result, execution_time)
        
    def do_exploit(self, args):
        """Alias for run command"""
        self.do_run(args)
        
    def _display_result(self, result: Dict[str, Any], execution_time: float):
        """Display execution results"""
        print(f"\n{Fore.CYAN}Execution Results:{Style.RESET_ALL}")
        print("=" * 50)
        
        status = result.get("result")
        if status == ExploitResult.SUCCESS or status == "success":
            print(f"{Fore.GREEN}[+] Module executed successfully{Style.RESET_ALL}")
        elif status == ExploitResult.FAILED or status == "failed":
            print(f"{Fore.YELLOW}[-] Module execution failed{Style.RESET_ALL}")
        elif status == ExploitResult.ERROR or status == "error":
            print(f"{Fore.RED}[-] Module execution error{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[?] Unknown result status{Style.RESET_ALL}")
            
        # Show message if present
        if "message" in result:
            print(f"Message: {result['message']}")
            
        # Show data if present
        if "data" in result and result["data"]:
            print(f"\n{Fore.CYAN}Result Data:{Style.RESET_ALL}")
            data = result["data"]
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, (list, dict)):
                        print(f"  {key}: {len(value)} items")
                    else:
                        print(f"  {key}: {value}")
            else:
                print(f"  {data}")
                
        print(f"\nExecution time: {execution_time:.2f} seconds")
        
    def do_search(self, args):
        """
        Search for modules
        Usage: search <query>
        Example: search reentrancy
        """
        if not args:
            print("Usage: search <query>")
            return
            
        results = self.framework.module_manager.search_modules(args)
        if results:
            print(f"\n{Fore.CYAN}Search Results for '{args}':{Style.RESET_ALL}")
            print("=" * 50)
            for i, module in enumerate(results, 1):
                print(f"{i:3}. {module}")
            print(f"\nFound {len(results)} matching modules")
        else:
            print(f"{Fore.YELLOW}[-] No modules found matching '{args}'{Style.RESET_ALL}")
            
    def do_exit(self, args):
        """Exit the console"""
        print(f"{Fore.GREEN}[+] Goodbye!{Style.RESET_ALL}")
        return True
        
    def do_quit(self, args):
        """Alias for exit"""
        return self.do_exit(args)
        
    def do_EOF(self, args):
        """Handle Ctrl+D"""
        print()  # New line
        return self.do_exit(args)

def main():
    """Main entry point for console interface"""
    try:
        console = SmartSploitConsole()
        console.cmdloop()
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}[+] Goodbye!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Console error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
