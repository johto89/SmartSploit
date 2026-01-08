#!/usr/bin/env python3
"""
SmartSploit Console Launcher
Run the SmartSploit command line interface
"""

import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run console
from smartsploit.interfaces.console import main

if __name__ == '__main__':
    main()