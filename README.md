# AMAT
---
# AMAT - Android Memory Acquisition Tool

<div align="center">

![AMAT Logo](https://img.shields.io/badge/AMAT-v1.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=for-the-badge)

**Professional-Grade Android Forensic Acquisition & Analysis Framework**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Output Structure](#-output-structure)
- [Analysis Capabilities](#-analysis-capabilities)
- [Technical Specifications](#-technical-specifications)
- [Best Practices](#-best-practices)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## 🎯 Overview

**AMAT (Android Memory Acquisition Tool)** is a comprehensive, production-ready forensic solution designed for digital forensic investigators, incident responders, and security professionals. Built with Python, AMAT combines powerful data acquisition capabilities with interactive analysis tools to streamline mobile forensic examinations.

### 🎖️ **Project Highlights**

- **🏆 Enterprise-Grade**: Production-ready code with comprehensive error handling
- **🔒 Forensically Sound**: Maintains chain of custody and evidence integrity
- **⚡ Efficient**: Optimized for large-scale data acquisition (5-20 GB in 8-15 minutes)
- **🎓 Educational**: Clean, well-documented code suitable for learning
- **🔧 Practical**: Real-world tool used in actual forensic investigations

### 💼 **Use Cases**

- 👮 **Law Enforcement**: Criminal investigations requiring mobile device evidence
- 🏢 **Corporate Security**: Internal investigations and incident response
- 🔍 **Digital Forensics**: Professional forensic examinations
- 🛡️ **Security Audits**: Mobile device security assessments
- 🎓 **Academic Research**: Mobile forensics research and education

---

## ✨ Features

### 🔍 **Comprehensive Data Acquisition**

#### **Volatile Memory**
- ✅ Running process enumeration with memory statistics
- ✅ Memory maps for top 50 processes
- ✅ System memory information (`/proc/meminfo`)

#### **Application Data**
- ✅ SQLite databases from all installed applications
- ✅ Shared preferences (XML configuration files)
- ✅ Application cache and internal storage
- ✅ 243 packages processed automatically

#### **Communication Evidence**
- ✅ Contact lists (names, phone numbers, emails)
- ✅ SMS/MMS messages with timestamps
- ✅ Call logs (incoming, outgoing, missed)
- ✅ WhatsApp databases and media (rooted devices)

#### **Media & Documents**
- ✅ Photos (JPEG, PNG, GIF, WebP)
- ✅ Videos (MP4, 3GP, AVI, MKV)
- ✅ Audio files (MP3, M4A, WAV)
- ✅ Documents (PDF, Office files)

#### **System Artifacts**
- ✅ System logs (logcat: main, system, events)
- ✅ Kernel logs (dmesg - requires root)
- ✅ Package lists (all, system, third-party)
- ✅ System settings and configurations

### 🔬 **Interactive Analysis Tools**

- 🔎 **Database Explorer**: SQLite database analysis with table/column inspection
- 📱 **Contact Extraction**: Automated contact list parsing
- 💬 **Message Recovery**: SMS/MMS message extraction with metadata
- 📊 **Process Analysis**: Volatile memory examination
- 🔍 **Keyword Search**: Full-text search across all acquired files
- 📈 **Statistical Reports**: Comprehensive acquisition summaries

### 🛡️ **Advanced Capabilities**

- 🔐 **Root Detection**: Automatic detection with fallback strategies
- 🪟 **Windows Compatible**: Path sanitization for cross-platform support
- ⚡ **Multi-Strategy Extraction**: 3-tier extraction methodology
- 📦 **Large File Handling**: Supports files up to 500 MB
- 🔄 **Retry Logic**: Automatic retry with exponential backoff
- 📝 **Professional Reporting**: JSON + TXT format reports

---

## 🏗️ Architecture

### **System Design**

```
┌─────────────────────────────────────────────────────────────┐
│                    AMAT v5.0 Complete                       │
│                 Unified Forensic Framework                  │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
┌───────────────────┐                 ┌───────────────────┐
│  Acquisition      │                 │  Analysis         │
│  Engine           │                 │  Engine           │
├───────────────────┤                 ├───────────────────┤
│ • Root Detection  │                 │ • DB Explorer     │
│ • File Extraction │                 │ • Contact Parser  │
│ • Memory Capture  │                 │ • SMS Extractor   │
│ • Media Download  │                 │ • File Search     │
│ • Error Handling  │                 │ • Report Gen      │
└───────────────────┘                 └───────────────────┘
        │                                       │
        └───────────────────┬───────────────────┘
                            ▼
                ┌───────────────────────┐
                │   ADB Interface       │
                │  (Android Debug       │
                │   Bridge)             │
                └───────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │   Android Device      │
                │  (Rooted/Non-rooted)  │
                └───────────────────────┘
```

### **Technology Stack**

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | Python 3.8+ | Core implementation |
| **Interface** | ADB (Android Debug Bridge) | Device communication |
| **Database** | SQLite3 | Evidence parsing |
| **Data Format** | JSON, XML, TXT | Reporting & config |
| **File System** | pathlib | Cross-platform paths |
| **Concurrency** | subprocess | Command execution |

---

## 🚀 Installation

### **Prerequisites**

| Requirement | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.8+ | Runtime environment |
| **ADB** | 1.0.39+ | Device communication |
| **USB Drivers** | Latest | Device recognition |
| **Storage** | 50 GB+ | Evidence storage |
| **RAM** | 8 GB+ (16 GB recommended) | Performance |

### **Step 1: Clone Repository**

```bash
git clone https://github.com/yourusername/AMAT.git
cd AMAT
```

### **Step 2: Install ADB**

#### **Windows**
```powershell
# Download Platform Tools
# https://developer.android.com/studio/releases/platform-tools

# Extract to C:\platform-tools
# Add to PATH environment variable

# Verify installation
adb version
```

#### **macOS**
```bash
# Using Homebrew
brew install android-platform-tools

# Verify
adb version
```

#### **Linux (Ubuntu/Debian)**
```bash
sudo apt-get update
sudo apt-get install android-tools-adb

# Verify
adb version
```

### **Step 3: Verify Installation**

```bash
# Check Python version
python --version  # Should be 3.8 or higher

# Check ADB
adb version       # Should show version 1.0.39+

# Test AMAT
python amat_complete.py
```

### **Step 4: Enable USB Debugging on Android Device**

1. **Settings** → **About Phone**
2. Tap **Build Number** 7 times (enables Developer Options)
3. **Settings** → **Developer Options**
4. Enable **USB Debugging**
5. Connect device via USB
6. Authorize computer when prompted

---

## 🎬 Quick Start

### **Three-Line Acquisition**

```bash
# Connect device → Run AMAT → Select Quick Mode
python amat_complete.py
# Select: 3 (Quick Mode)
# Wait 8-15 minutes → Start analyzing!
```

### **Expected Output**

```
================================================================================
  AMAT v5.0-COMPLETE
  Complete Forensic Solution - Acquisition Module
================================================================================

[10:15:30] [INFO] Device: Samsung Galaxy S21
[10:15:30] [INFO] Android: 13 (SDK 33)
[10:15:30] [SUCCESS] ✓ Root access available

[Acquisition Progress...]

================================================================================
  ACQUISITION COMPLETE
================================================================================

Output: forensic_acquisition\case_20260213_101530
Time: 8.9 minutes

Data: 15.2 GB
Files: 1,847
Databases: 127

Breakdown:
  Volatile:      12.3 MB (49 maps)
  Apps:        2,456.8 MB (127 DBs)
  Media:      12,234.5 MB (1,247P/89V)
  System:        234.7 MB
```

---

## 📖 Usage Guide

### **Operational Modes**

AMAT offers three distinct operational modes:

#### **Mode 1: Acquisition Only**
```bash
python amat_complete.py
# Select: 1

# Use Case: Field acquisition without immediate analysis
# Output: Timestamped case directory ready for lab analysis
```

#### **Mode 2: Analysis Only**
```bash
python amat_complete.py
# Select: 2
# Enter: forensic_acquisition\case_20260213_101530

# Use Case: Analyze previously acquired evidence
# No device connection required
```

#### **Mode 3: Quick Mode (Recommended)**
```bash
python amat_complete.py
# Select: 3

# Use Case: Complete workflow - acquire then analyze
# Best for time-sensitive investigations
```

### **Interactive Analysis Menu**

```
================================================================================
FORENSIC ANALYZER - INTERACTIVE MENU
================================================================================

1.  Overview & Summary          - View case details
2.  List All Files             - Browse acquired files
3.  Analyze Volatile Memory    - Process & memory analysis
4.  Find All Databases         - Discover SQLite databases
5.  Analyze Specific Database  - Deep DB inspection
6.  Extract Contacts           - Parse contact list
7.  Extract SMS Messages       - Recover text messages
8.  Analyze Installed Packages - List all applications
9.  Search Files               - Keyword search
0.  Exit

Enter choice:
```

---

## 📁 Output Structure

All acquired data is organized in a forensically sound directory structure:

```
forensic_acquisition/
└── case_YYYYMMDD_HHMMSS/
    ├── 01_VOLATILE/              # Memory artifacts
    │   ├── process_list.txt
    │   ├── meminfo.txt
    │   └── maps_*.txt (49 files)
    │
    ├── 02_APP_DATA/              # Application data
    │   ├── com.android.contacts/
    │   ├── com.android.providers.telephony/
    │   ├── com.whatsapp/
    │   └── ... (243 apps)
    │
    ├── 03_DATABASES/             # Consolidated databases
    │
    ├── 04_MEDIA/                 # Media files
    │   ├── photos/
    │   ├── videos/
    │   └── audio/
    │
    ├── 05_DOCUMENTS/             # Documents
    │
    ├── 06_DOWNLOADS/             # Downloads folder
    │
    ├── 07_WHATSAPP/              # WhatsApp data
    │
    ├── 08_BROWSER/               # Browser artifacts
    │
    ├── 09_SYSTEM/                # System logs
    │   ├── logcat_main.txt
    │   ├── packages_all.txt
    │   └── settings_*.txt
    │
    ├── 10_REPORTS/               # Forensic reports
    │   ├── EXECUTIVE_SUMMARY.txt
    │   └── acquisition_log.json
    │
    └── 11_LOGS/                  # Error logs
```

---

## 🔬 Analysis Capabilities

### **Database Analysis Example**

```python
# Automatic SQLite parsing
Enter choice: 5
Select database: 2 (mmssms.db)

Output:
================================================================================
DATABASE ANALYSIS: mmssms.db
================================================================================
Path: .../com.android.providers.telephony/databases/mmssms.db
Size: 2.3 MB

Tables: 15
--------------------------------------------------------------------------------

Table: sms
  Rows: 1,247
  Columns: _id, thread_id, address, date, body, type
  Sample data:
    [1, 1, '+1234567890', 1707534000000, 'Meeting at 3pm', 1]
    [2, 1, '+1234567890', 1707534120000, 'Confirmed', 2]
```

### **Contact Extraction Example**

```python
Enter choice: 6

Output:
================================================================================
CONTACTS EXTRACTION
================================================================================

Found 347 contact entries:
--------------------------------------------------------------------------------
1. ('John Doe', '+1-555-0123', 'john.doe@email.com')
2. ('Jane Smith', '+1-555-0456', 'jane.smith@company.com')
3. ('Mike Johnson', '+1-555-0789', None)
...
```

### **Keyword Search Example**

```python
Enter choice: 9
Enter search term: "project alpha"

Output:
================================================================================
SEARCHING FOR: 'project alpha'
================================================================================

Found in 12 files:

09_SYSTEM/logcat_main.txt:
  Line 1234: I/Email: Subject: Project Alpha status update
  Line 2456: D/Calendar: Event: Project Alpha meeting @ 2pm

02_APP_DATA/com.android.messaging/databases/bugle_db:
  [Database entry containing "project alpha"]
```

---

## 🔧 Technical Specifications

### **Capabilities Matrix**

| Feature | Non-Rooted | Rooted |
|---------|-----------|--------|
| Process List | ✅ Partial | ✅ Full |
| Memory Maps | ⚠️ Limited | ✅ 50+ maps |
| App Databases | ❌ Restricted | ✅ Full access |
| Contacts | ❌ No | ✅ Yes |
| SMS/MMS | ❌ No | ✅ Yes |
| Call Logs | ❌ No | ✅ Yes |
| Media Files | ✅ Yes | ✅ Yes |
| Documents | ✅ Yes | ✅ Yes |
| Downloads | ✅ Yes | ✅ Yes |
| Browser Data | ❌ No | ✅ Yes |
| WhatsApp | ⚠️ Partial | ✅ Full |
| System Logs | ⚠️ Partial | ✅ Full |

### **Performance Metrics**

| Metric | Value |
|--------|-------|
| **Acquisition Speed** | ~1.5 GB/minute |
| **Typical Time** | 8-15 minutes |
| **Max File Size** | 500 MB |
| **Max Total Size** | 25 GB |
| **Path Length Limit** | 200 characters |
| **Retry Attempts** | 3 per file |
| **Supported Android** | 6.0+ (API 23+) |

### **Data Integrity**

- ✅ SHA-256 hashing for verification
- ✅ Timestamped acquisitions
- ✅ Chain of custody preservation
- ✅ Error logging and tracking
- ✅ Non-destructive extraction

---

## 📚 Best Practices

### **Chain of Custody**

1. **Document** device details before acquisition
2. **Photograph** device state and serial number
3. **Record** acquisition timestamp
4. **Hash** evidence directory after acquisition
5. **Store** on write-protected media
6. **Maintain** detailed case notes

### **Evidence Handling**

```bash
# Recommended workflow
1. Enable Airplane Mode (prevent remote wipe)
2. Keep device charged
3. Do NOT disconnect during acquisition
4. Create immediate backup
5. Calculate hash values
   $ md5sum case_20260213_101530/
   $ sha256sum case_20260213_101530/
```

### **Legal Compliance**

- ⚖️ Obtain proper authorization (warrant/consent)
- 📋 Follow organizational policies
- 🔒 Protect privacy rights
- 📝 Document all procedures
- 👨‍⚖️ Maintain admissibility standards

---

## 🐛 Troubleshooting

### **Common Issues**

#### **Device Not Detected**

```bash
# Check USB debugging
adb devices

# If unauthorized, re-authorize on device
adb kill-server
adb start-server

# Check drivers
# Windows: Install manufacturer USB drivers
# Linux: Add udev rules for device
```

#### **Low Data Volume**

```bash
# Check root status
adb shell su -c id
# If fails: Device not rooted (limits data access)

# Verify permissions
adb shell ls -la /data/data/
# If permission denied: Expected on non-rooted device
```

#### **Path Too Long Errors**

```bash
# AMAT auto-sanitizes paths, but if issues persist:

# Windows: Enable long path support
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem
# Set LongPathsEnabled = 1

# Or move acquisition folder closer to root
C:\forensics\  # Better than
C:\Users\Username\Documents\Work\Cases\2026\February\
```

---

## 🤝 Contributing

Contributions are welcome! This project follows industry-standard development practices.

### **Development Setup**

```bash
# Fork and clone
git clone https://github.com/yourusername/AMAT.git
cd AMAT

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
python amat_complete.py

# Commit with conventional commits
git commit -m "feat: add advanced memory analysis"

# Push and create PR
git push origin feature/amazing-feature
```

### **Code Standards**

- ✅ PEP 8 compliant
- ✅ Type hints where applicable
- ✅ Comprehensive docstrings
- ✅ Error handling for all I/O
- ✅ Logging for debugging

### **Pull Request Process**

1. Update documentation
2. Add test cases if applicable
3. Ensure all existing tests pass
4. Update CHANGELOG.md
5. Request review from maintainers

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### **Permissions**
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use

### **Conditions**
- 📋 License and copyright notice

### **Limitations**
- ⚠️ No liability
- ⚠️ No warranty

---

## 🎓 Acknowledgments

### **Technologies Used**

- **Python** - Core programming language
- **ADB** - Android Debug Bridge by Google
- **SQLite** - Database engine
- **pathlib** - Modern path handling

### **Inspiration**

This project was developed to address the need for an open-source, professional-grade Android forensic tool that combines acquisition and analysis in a unified framework.

### **Educational Value**

AMAT demonstrates:
- Production-ready Python development
- Forensic tool engineering
- Cross-platform compatibility
- Error handling best practices
- Clean code architecture

---

## 📞 Contact & Support

### **Author**
- **Name**: Aayush Saxena
- **Role**: Digital Forensics Engineer
- **LinkedIn**: [Connect with me](https://www.linkedin.com/in/yourprofile)
- **GitHub**: [@yourusername](https://github.com/yourusername)


---

