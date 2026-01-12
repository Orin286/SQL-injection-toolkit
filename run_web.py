#!/usr/bin/env python3
"""
Web Interface Launcher for SQL Injection Toolkit
"""

import sys
import os
from web.app import app

def main():
    """Main launcher function"""
    print("""
===============================================
           SQL INJECTION TOOLKIT
           Web Interface Launcher
===============================================
""")
    
    print("Starting web interface...")
    print("URL: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("-" * 60)
    
    try:
        # Run Flask app
        app.run(debug=False, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\nWeb interface stopped")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
