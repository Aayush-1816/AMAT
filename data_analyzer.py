#!/usr/bin/env python3
"""
Forensic Data Analyzer
Analyzes and displays data from AMAT forensic acquisition

Features:
- Read and display memory maps
- Parse SQLite databases
- View system logs
- Extract contacts, messages, call logs
- Search across all files
- Generate analysis reports

Author: Forensic Research Project
Version: 1.0
"""

import os
import sys
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional
import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

class AnalyzerConfig:
    MAX_DISPLAY_LINES = 100
    MAX_FILE_SIZE_MB = 50
    VERBOSE = True

# ============================================================================
# FORENSIC DATA ANALYZER
# ============================================================================

class ForensicAnalyzer:
    def __init__(self, case_dir: str):
        self.case_dir = Path(case_dir)
        
        if not self.case_dir.exists():
            raise ValueError(f"Case directory not found: {case_dir}")
        
        self.dirs = {
            "volatile": self.case_dir / "01_VOLATILE",
            "app_data": self.case_dir / "02_APP_DATA",
            "databases": self.case_dir / "03_DATABASES",
            "media": self.case_dir / "04_MEDIA",
            "documents": self.case_dir / "05_DOCUMENTS",
            "downloads": self.case_dir / "06_DOWNLOADS",
            "whatsapp": self.case_dir / "07_WHATSAPP",
            "browser": self.case_dir / "08_BROWSER",
            "system": self.case_dir / "09_SYSTEM",
            "reports": self.case_dir / "10_REPORTS"
        }
        
        self.databases = []
        self.memory_maps = []
        
    # ========================================================================
    # OVERVIEW AND SUMMARY
    # ========================================================================
    
    def print_overview(self):
        """Print case overview"""
        print("\n" + "="*80)
        print("FORENSIC CASE ANALYSIS")
        print("="*80)
        print(f"\nCase Directory: {self.case_dir}")
        print(f"Case ID: {self.case_dir.name}")
        
        # Read executive summary if available
        summary_file = self.dirs["reports"] / "EXECUTIVE_SUMMARY.txt"
        if summary_file.exists():
            print("\n" + "-"*80)
            print("EXECUTIVE SUMMARY")
            print("-"*80)
            with open(summary_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Print first 50 lines
                lines = content.split('\n')[:50]
                print('\n'.join(lines))
        
        print("\n" + "="*80)
    
    def list_all_files(self):
        """List all acquired files by category"""
        print("\n" + "="*80)
        print("ACQUIRED FILES BY CATEGORY")
        print("="*80)
        
        for name, directory in self.dirs.items():
            if not directory.exists():
                continue
            
            files = list(directory.rglob('*'))
            file_count = len([f for f in files if f.is_file()])
            total_size = sum(f.stat().st_size for f in files if f.is_file())
            size_mb = total_size / 1024 / 1024
            
            print(f"\n{name.upper().replace('_', ' ')}:")
            print(f"  Files: {file_count}")
            print(f"  Size: {size_mb:.2f} MB")
            
            if file_count > 0 and file_count <= 20:
                for f in sorted([f for f in files if f.is_file()]):
                    rel_path = f.relative_to(directory)
                    print(f"    - {rel_path}")
            elif file_count > 20:
                file_list = sorted([f for f in files if f.is_file()])
                print(f"    [Showing first 10 of {file_count} files]")
                for f in file_list[:10]:
                    rel_path = f.relative_to(directory)
                    print(f"    - {rel_path}")
                print(f"    ... and {file_count - 10} more")
    
    # ========================================================================
    # VOLATILE MEMORY ANALYSIS
    # ========================================================================
    
    def analyze_volatile_memory(self):
        """Analyze volatile memory artifacts"""
        print("\n" + "="*80)
        print("VOLATILE MEMORY ANALYSIS")
        print("="*80)
        
        volatile_dir = self.dirs["volatile"]
        
        # Process list
        process_file = volatile_dir / "process_list.txt"
        if process_file.exists():
            print("\nPROCESS LIST:")
            print("-"*80)
            with open(process_file, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')[:30]  # First 30 lines
                print('\n'.join(lines))
        
        # Memory maps
        map_files = list(volatile_dir.glob("maps_*.txt"))
        if map_files:
            print(f"\n\nMEMORY MAPS: Found {len(map_files)} memory maps")
            print("-"*80)
            print("Sample maps (first 5):")
            
            for idx, map_file in enumerate(sorted(map_files)[:5], 1):
                print(f"\n{idx}. {map_file.name}")
                with open(map_file, 'r', encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()[:15]  # First 15 lines
                    print(''.join(lines))
        
        # Memory info
        meminfo = volatile_dir / "meminfo.txt"
        if meminfo.exists():
            print("\n\nSYSTEM MEMORY INFO:")
            print("-"*80)
            with open(meminfo, 'r', encoding='utf-8') as f:
                lines = f.readlines()[:20]
                print(''.join(lines))
    
    # ========================================================================
    # DATABASE ANALYSIS
    # ========================================================================
    
    def find_databases(self):
        """Find all SQLite databases"""
        print("\n" + "="*80)
        print("DATABASE DISCOVERY")
        print("="*80)
        
        db_extensions = ['.db', '.sqlite', '.db-wal', '.db-shm']
        databases = []
        
        # Search in app_data
        app_data_dir = self.dirs["app_data"]
        if app_data_dir.exists():
            for ext in db_extensions:
                databases.extend(app_data_dir.rglob(f"*{ext}"))
        
        # Filter to just .db and .sqlite (not WAL/SHM files)
        databases = [db for db in databases if db.suffix in ['.db', '.sqlite']]
        
        print(f"\nFound {len(databases)} databases:\n")
        
        categorized = {}
        for db in databases:
            # Get app name from path
            try:
                parts = db.parts
                app_data_idx = parts.index("02_APP_DATA")
                if app_data_idx + 1 < len(parts):
                    app_name = parts[app_data_idx + 1]
                else:
                    app_name = "Unknown"
            except:
                app_name = "Unknown"
            
            if app_name not in categorized:
                categorized[app_name] = []
            categorized[app_name].append(db)
        
        for app_name, dbs in sorted(categorized.items()):
            print(f"\n{app_name}:")
            for db in dbs:
                size_kb = db.stat().st_size / 1024
                print(f"  - {db.name} ({size_kb:.1f} KB)")
        
        self.databases = databases
        return databases
    
    def analyze_database(self, db_path: Path):
        """Analyze a specific SQLite database"""
        print("\n" + "="*80)
        print(f"DATABASE ANALYSIS: {db_path.name}")
        print("="*80)
        print(f"Path: {db_path}")
        print(f"Size: {db_path.stat().st_size / 1024:.1f} KB")
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            print(f"\nTables: {len(tables)}")
            print("-"*80)
            
            for table_name, in tables:
                print(f"\nTable: {table_name}")
                
                # Get row count
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                    count = cursor.fetchone()[0]
                    print(f"  Rows: {count}")
                except:
                    print(f"  Rows: [Unable to count]")
                
                # Get column info
                try:
                    cursor.execute(f"PRAGMA table_info('{table_name}')")
                    columns = cursor.fetchall()
                    print(f"  Columns: {', '.join([col[1] for col in columns])}")
                except:
                    print(f"  Columns: [Unable to retrieve]")
                
                # Show sample data (first 3 rows)
                try:
                    cursor.execute(f"SELECT * FROM '{table_name}' LIMIT 3")
                    rows = cursor.fetchall()
                    
                    if rows:
                        print(f"  Sample data:")
                        for row in rows:
                            # Truncate long values
                            display_row = []
                            for val in row:
                                if val is None:
                                    display_row.append("NULL")
                                elif isinstance(val, bytes):
                                    display_row.append(f"<BLOB:{len(val)}bytes>")
                                else:
                                    str_val = str(val)
                                    if len(str_val) > 50:
                                        display_row.append(str_val[:50] + "...")
                                    else:
                                        display_row.append(str_val)
                            print(f"    {display_row}")
                except Exception as e:
                    print(f"  Sample data: [Error: {e}]")
            
            conn.close()
            
        except sqlite3.Error as e:
            print(f"\nError accessing database: {e}")
        except Exception as e:
            print(f"\nUnexpected error: {e}")
    
    # ========================================================================
    # CONTACTS EXTRACTION
    # ========================================================================
    
    def extract_contacts(self):
        """Extract contacts from contacts database"""
        print("\n" + "="*80)
        print("CONTACTS EXTRACTION")
        print("="*80)
        
        # Find contacts database
        contacts_dbs = [
            self.case_dir / "02_APP_DATA" / "com.android.providers.contacts" / "data" / "data" / 
            "com.android.providers.contacts" / "databases" / "contacts2.db"
        ]
        
        contacts_found = False
        
        for db_path in contacts_dbs:
            if not db_path.exists():
                continue
            
            contacts_found = True
            print(f"\nAnalyzing: {db_path.name}")
            
            try:
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                
                # Check if contacts table exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='data';")
                if not cursor.fetchone():
                    print("  No 'data' table found")
                    continue
                
                # Extract contacts
                query = """
                SELECT DISTINCT data1, data2, data3 
                FROM data 
                WHERE mimetype_id IN (
                    SELECT _id FROM mimetypes WHERE mimetype LIKE '%name%' OR mimetype LIKE '%phone%'
                )
                LIMIT 50
                """
                
                cursor.execute(query)
                contacts = cursor.fetchall()
                
                print(f"\nFound {len(contacts)} contact entries:")
                print("-"*80)
                
                for idx, contact in enumerate(contacts[:20], 1):
                    print(f"{idx}. {contact}")
                
                if len(contacts) > 20:
                    print(f"... and {len(contacts) - 20} more")
                
                conn.close()
                
            except Exception as e:
                print(f"  Error: {e}")
        
        if not contacts_found:
            print("\nNo contacts database found")
    
    # ========================================================================
    # SMS MESSAGES EXTRACTION
    # ========================================================================
    
    def extract_sms(self):
        """Extract SMS messages"""
        print("\n" + "="*80)
        print("SMS MESSAGES EXTRACTION")
        print("="*80)
        
        # Find SMS database
        sms_db = self.case_dir / "02_APP_DATA" / "com.android.providers.telephony" / "data" / "data" / \
                 "com.android.providers.telephony" / "databases" / "mmssms.db"
        
        if not sms_db.exists():
            print("\nNo SMS database found")
            return
        
        print(f"\nAnalyzing: {sms_db.name}")
        
        try:
            conn = sqlite3.connect(str(sms_db))
            cursor = conn.cursor()
            
            # Get SMS count
            cursor.execute("SELECT COUNT(*) FROM sms")
            count = cursor.fetchone()[0]
            
            print(f"\nTotal SMS messages: {count}")
            
            if count > 0:
                # Get recent messages
                query = """
                SELECT address, date, body, type 
                FROM sms 
                ORDER BY date DESC 
                LIMIT 20
                """
                
                cursor.execute(query)
                messages = cursor.fetchall()
                
                print("\nRecent messages:")
                print("-"*80)
                
                for idx, (address, date, body, msg_type) in enumerate(messages, 1):
                    # Convert timestamp
                    try:
                        dt = datetime.datetime.fromtimestamp(int(date) / 1000)
                        date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        date_str = str(date)
                    
                    msg_type_str = "Received" if msg_type == 1 else "Sent"
                    
                    # Truncate long messages
                    if body and len(body) > 100:
                        body = body[:100] + "..."
                    
                    print(f"\n{idx}. [{date_str}] {msg_type_str}")
                    print(f"   From/To: {address}")
                    print(f"   Message: {body}")
            
            conn.close()
            
        except Exception as e:
            print(f"\nError: {e}")
    
    # ========================================================================
    # CALL LOG EXTRACTION
    # ========================================================================
    
    def extract_call_logs(self):
        """Extract call logs"""
        print("\n" + "="*80)
        print("CALL LOGS EXTRACTION")
        print("="*80)
        
        # Find call log database
        dialer_db = self.case_dir / "02_APP_DATA" / "com.android.dialer" / "data" / "data" / \
                    "com.android.dialer" / "databases" / "dialer.db"
        
        if not dialer_db.exists():
            print("\nNo call log database found")
            return
        
        print(f"\nAnalyzing: {dialer_db.name}")
        
        try:
            conn = sqlite3.connect(str(dialer_db))
            cursor = conn.cursor()
            
            # List all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            print(f"\nTables: {[t[0] for t in tables]}")
            
            # Try to find call-related tables
            for table_name, in tables:
                if 'call' in table_name.lower():
                    cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                    count = cursor.fetchone()[0]
                    print(f"\nTable '{table_name}': {count} entries")
                    
                    if count > 0:
                        cursor.execute(f"SELECT * FROM '{table_name}' LIMIT 5")
                        rows = cursor.fetchall()
                        for row in rows:
                            print(f"  {row}")
            
            conn.close()
            
        except Exception as e:
            print(f"\nError: {e}")
    
    # ========================================================================
    # SYSTEM LOGS ANALYSIS
    # ========================================================================
    
    def analyze_system_logs(self):
        """Analyze system logs"""
        print("\n" + "="*80)
        print("SYSTEM LOGS ANALYSIS")
        print("="*80)
        
        system_dir = self.dirs["system"]
        
        log_files = {
            "logcat_main.txt": "Main System Log",
            "logcat_system.txt": "System Log",
            "logcat_events.txt": "Events Log",
            "dmesg.txt": "Kernel Log"
        }
        
        for filename, description in log_files.items():
            log_file = system_dir / filename
            
            if not log_file.exists():
                continue
            
            print(f"\n{description}: {filename}")
            print("-"*80)
            
            with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                
                print(f"Total lines: {len(lines)}")
                
                # Show first 20 lines
                print("\nFirst 20 lines:")
                for line in lines[:20]:
                    print(line.rstrip())
                
                # Show last 20 lines
                if len(lines) > 40:
                    print("\n... [content omitted] ...\n")
                    print("Last 20 lines:")
                    for line in lines[-20:]:
                        print(line.rstrip())
    
    # ========================================================================
    # PACKAGE INFORMATION
    # ========================================================================
    
    def analyze_packages(self):
        """Analyze installed packages"""
        print("\n" + "="*80)
        print("INSTALLED PACKAGES ANALYSIS")
        print("="*80)
        
        pkg_file = self.dirs["system"] / "packages_all.txt"
        
        if not pkg_file.exists():
            print("\nNo package list found")
            return
        
        with open(pkg_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        packages = []
        for line in lines:
            if line.startswith('package:'):
                pkg = line.replace('package:', '').strip()
                if '=' in pkg:
                    path, name = pkg.split('=', 1)
                    packages.append((name, path))
        
        print(f"\nTotal packages: {len(packages)}")
        
        # Categorize packages
        system_pkgs = [p for p in packages if p[0].startswith('com.android.') or p[0].startswith('android.')]
        third_party = [p for p in packages if p not in system_pkgs]
        
        print(f"System packages: {len(system_pkgs)}")
        print(f"Third-party apps: {len(third_party)}")
        
        print("\nThird-party applications:")
        print("-"*80)
        
        for name, path in sorted(third_party):
            print(f"  {name}")
            print(f"    Path: {path}")
    
    # ========================================================================
    # SEARCH FUNCTIONALITY
    # ========================================================================
    
    def search_files(self, search_term: str):
        """Search for term across all text files"""
        print("\n" + "="*80)
        print(f"SEARCHING FOR: '{search_term}'")
        print("="*80)
        
        results = []
        
        # Search in text files
        for root, dirs, files in os.walk(self.case_dir):
            for filename in files:
                if filename.endswith(('.txt', '.json', '.xml', '.log')):
                    filepath = Path(root) / filename
                    
                    # Skip large files
                    if filepath.stat().st_size > AnalyzerConfig.MAX_FILE_SIZE_MB * 1024 * 1024:
                        continue
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                            content = f.read()
                            
                            if search_term.lower() in content.lower():
                                # Find line numbers
                                lines = content.split('\n')
                                matching_lines = []
                                
                                for idx, line in enumerate(lines, 1):
                                    if search_term.lower() in line.lower():
                                        matching_lines.append((idx, line.strip()))
                                
                                results.append((filepath, matching_lines))
                    except:
                        continue
        
        if results:
            print(f"\nFound in {len(results)} files:\n")
            
            for filepath, matching_lines in results:
                rel_path = filepath.relative_to(self.case_dir)
                print(f"\n{rel_path}:")
                
                for line_num, line in matching_lines[:5]:  # First 5 matches per file
                    if len(line) > 100:
                        line = line[:100] + "..."
                    print(f"  Line {line_num}: {line}")
                
                if len(matching_lines) > 5:
                    print(f"  ... and {len(matching_lines) - 5} more matches")
        else:
            print("\nNo results found")
    
    # ========================================================================
    # INTERACTIVE MENU
    # ========================================================================
    
    def interactive_menu(self):
        """Interactive analysis menu"""
        while True:
            print("\n" + "="*80)
            print("FORENSIC ANALYZER - INTERACTIVE MENU")
            print("="*80)
            print("\n1.  Overview & Summary")
            print("2.  List All Files")
            print("3.  Analyze Volatile Memory")
            print("4.  Find All Databases")
            print("5.  Analyze Specific Database")
            print("6.  Extract Contacts")
            print("7.  Extract SMS Messages")
            print("8.  Extract Call Logs")
            print("9.  Analyze System Logs")
            print("10. Analyze Installed Packages")
            print("11. Search Files")
            print("12. Generate Full Report")
            print("0.  Exit")
            
            choice = input("\nEnter choice: ").strip()
            
            if choice == '0':
                print("\nExiting...")
                break
            elif choice == '1':
                self.print_overview()
            elif choice == '2':
                self.list_all_files()
            elif choice == '3':
                self.analyze_volatile_memory()
            elif choice == '4':
                self.find_databases()
            elif choice == '5':
                dbs = self.find_databases()
                if dbs:
                    print("\nSelect database:")
                    for idx, db in enumerate(dbs, 1):
                        print(f"{idx}. {db.name}")
                    
                    try:
                        db_choice = int(input("\nEnter number: "))
                        if 1 <= db_choice <= len(dbs):
                            self.analyze_database(dbs[db_choice - 1])
                    except:
                        print("Invalid choice")
            elif choice == '6':
                self.extract_contacts()
            elif choice == '7':
                self.extract_sms()
            elif choice == '8':
                self.extract_call_logs()
            elif choice == '9':
                self.analyze_system_logs()
            elif choice == '10':
                self.analyze_packages()
            elif choice == '11':
                term = input("Enter search term: ").strip()
                if term:
                    self.search_files(term)
            elif choice == '12':
                self.generate_full_report()
            else:
                print("Invalid choice")
            
            input("\nPress Enter to continue...")
    
    def generate_full_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "="*80)
        print("GENERATING FULL ANALYSIS REPORT")
        print("="*80)
        
        report_file = self.case_dir / "ANALYSIS_REPORT.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            # Redirect stdout to file
            import sys
            old_stdout = sys.stdout
            sys.stdout = f
            
            print("COMPREHENSIVE FORENSIC ANALYSIS REPORT")
            print("="*80)
            print(f"Generated: {datetime.datetime.now()}")
            print(f"Case: {self.case_dir.name}\n")
            
            self.print_overview()
            self.list_all_files()
            self.find_databases()
            self.extract_contacts()
            self.extract_sms()
            self.extract_call_logs()
            self.analyze_packages()
            
            sys.stdout = old_stdout
        
        print(f"\nReport saved to: {report_file}")

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n" + "="*80)
    print("FORENSIC DATA ANALYZER")
    print("="*80)
    
    if len(sys.argv) > 1:
        case_dir = sys.argv[1]
    else:
        case_dir = input("\nEnter case directory path: ").strip()
    
    if not case_dir:
        print("Error: No case directory specified")
        sys.exit(1)
    
    try:
        analyzer = ForensicAnalyzer(case_dir)
        analyzer.interactive_menu()
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()