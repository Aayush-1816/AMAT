#!/usr/bin/env python3
"""
AMAT - Android Memory Acquisition Tool
PRODUCTION-READY Forensic Acquisition Framework v4.2

COMPLETE FIXES:
- Windows path compatibility (colon replacement, path length limits)
- Improved file extraction with better error recovery
- Enhanced memory map acquisition
- Better WhatsApp and media detection
- Comprehensive logging and reporting

Author: Forensic Research Project
Version: 4.2 PRODUCTION
License: Academic Use Only
"""

import subprocess
import hashlib
import os
import sys
import datetime
import json
import re
import shutil
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, asdict

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    VERSION = "4.2-PRODUCTION"
    TOOL_NAME = "AMAT"
    
    # Acquisition settings
    ACQUIRE_VOLATILE = True
    ACQUIRE_APP_DATA = True
    ACQUIRE_DATABASES = True
    ACQUIRE_MEDIA = True
    ACQUIRE_DOCUMENTS = True
    ACQUIRE_DOWNLOADS = True
    ACQUIRE_WHATSAPP = True
    ACQUIRE_SYSTEM_LOGS = True
    ACQUIRE_BROWSER_DATA = True
    
    # Limits
    MAX_FILE_SIZE_MB = 500
    MAX_FILES_PER_APP = 300
    MAX_MEDIA_FILES = 2000
    MAX_PATH_LENGTH = 200  # Windows safe path length
    
    # Output settings
    OUTPUT_DIR = "./forensic_acquisition"
    VERBOSE = True
    
    # Timeouts
    ADB_TIMEOUT = 30
    PULL_TIMEOUT = 180
    SHELL_TIMEOUT = 90
    
    # Performance
    SHOW_PROGRESS_EVERY = 50
    RETRY_ATTEMPTS = 2

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ProcessInfo:
    pid: int
    name: str
    user: str
    memory_kb: int

@dataclass
class AcquisitionStats:
    volatile_mb: float = 0.0
    app_data_mb: float = 0.0
    media_mb: float = 0.0
    documents_mb: float = 0.0
    downloads_mb: float = 0.0
    system_mb: float = 0.0
    total_mb: float = 0.0
    
    processes_scanned: int = 0
    memory_maps_acquired: int = 0
    apps_processed: int = 0
    databases_acquired: int = 0
    photos_acquired: int = 0
    videos_acquired: int = 0
    audio_acquired: int = 0
    documents_acquired: int = 0
    total_files: int = 0
    failed_files: int = 0
    path_errors: int = 0
    
    extraction_errors: int = 0

# ============================================================================
# PRODUCTION FORENSIC ACQUISITION ENGINE
# ============================================================================

class ProductionForensicAcquisition:
    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(Config.OUTPUT_DIR)
        self.case_dir = self.output_dir / f"case_{self.timestamp}"
        
        # Create directory structure
        self.dirs = {
            "volatile": self.case_dir / "01_VOLATILE",
            "app_data": self.case_dir / "02_APP_DATA",
            "databases": self.case_dir / "03_DATABASES",
            "media": self.case_dir / "04_MEDIA",
            "photos": self.case_dir / "04_MEDIA" / "photos",
            "videos": self.case_dir / "04_MEDIA" / "videos",
            "audio": self.case_dir / "04_MEDIA" / "audio",
            "documents": self.case_dir / "05_DOCUMENTS",
            "downloads": self.case_dir / "06_DOWNLOADS",
            "whatsapp": self.case_dir / "07_WHATSAPP",
            "browser": self.case_dir / "08_BROWSER",
            "system": self.case_dir / "09_SYSTEM",
            "reports": self.case_dir / "10_REPORTS",
            "logs": self.case_dir / "11_LOGS"
        }
        
        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        
        # Statistics and tracking
        self.stats = AcquisitionStats()
        self.device_info = {}
        self.log_entries = []
        self.extracted_files: Set[str] = set()
        self.failed_extractions: List[Dict] = []
        self.has_root = False
        self.temp_counter = 0
        
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def log(self, message: str, level: str = "INFO"):
        """Log message with timestamp"""
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "level": level,
            "message": message
        }
        self.log_entries.append(entry)
        
        if Config.VERBOSE:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")
    
    def _sanitize_path(self, path: str) -> str:
        """
        Sanitize path for Windows compatibility
        - Replace colons (except drive letters)
        - Replace invalid characters
        - Limit length
        - Handle long paths
        """
        # Split into parts
        parts = path.split('/')
        sanitized_parts = []
        
        for part in parts:
            if not part:
                continue
            
            # Replace problematic characters
            sanitized = part
            invalid_chars = [':', '*', '?', '"', '<', '>', '|', '\n', '\r', '\t']
            for char in invalid_chars:
                sanitized = sanitized.replace(char, '_')
            
            # Replace leading dots (hidden files on Unix cause issues on Windows)
            if sanitized.startswith('.'):
                sanitized = '_' + sanitized[1:]
            
            # Limit individual component length
            if len(sanitized) > 100:
                sanitized = sanitized[:100]
            
            sanitized_parts.append(sanitized)
        
        result = '/'.join(sanitized_parts)
        
        # Limit total path length
        if len(result) > Config.MAX_PATH_LENGTH:
            # Use hash for long paths
            hash_suffix = hashlib.md5(result.encode()).hexdigest()[:8]
            result = result[:Config.MAX_PATH_LENGTH-10] + '_' + hash_suffix
        
        return result
    
    def _adb(self, cmd: list, timeout: int = 30) -> Tuple[str, int]:
        """Execute ADB command with error handling"""
        full_cmd = ["adb"]
        if self.device_id:
            full_cmd.extend(["-s", self.device_id])
        full_cmd.extend(cmd)
        
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                timeout=timeout,
                text=True,
                errors='replace'
            )
            return result.stdout, result.returncode
        except subprocess.TimeoutExpired:
            self.log(f"ADB timeout: {' '.join(cmd)}", "WARNING")
            return "", -1
        except Exception as e:
            return f"Error: {e}", -1
    
    def _shell(self, cmd: str, as_root: bool = False, timeout: int = 30) -> Tuple[str, int]:
        """Execute shell command on device"""
        if as_root and self.has_root:
            return self._adb(["shell", "su", "-c", cmd], timeout=timeout)
        else:
            return self._adb(["shell", cmd], timeout=timeout)
    
    def _get_file_size_mb(self, filepath: Path) -> float:
        """Get file size in MB"""
        try:
            return filepath.stat().st_size / 1024 / 1024
        except:
            return 0.0
    
    def _add_to_stats(self, category: str, size_mb: float):
        """Update statistics"""
        if category == "volatile":
            self.stats.volatile_mb += size_mb
        elif category == "app_data":
            self.stats.app_data_mb += size_mb
        elif category == "media":
            self.stats.media_mb += size_mb
        elif category == "documents":
            self.stats.documents_mb += size_mb
        elif category == "downloads":
            self.stats.downloads_mb += size_mb
        elif category == "system":
            self.stats.system_mb += size_mb
        
        self.stats.total_mb += size_mb
        self.stats.total_files += 1
    
    # ========================================================================
    # ROOT DETECTION
    # ========================================================================
    
    def check_root_access(self) -> bool:
        """Check if device has root access"""
        self.log("Checking for root access...")
        
        stdout, code = self._adb(["shell", "su", "-c", "id"], timeout=5)
        
        if code == 0 and "uid=0" in stdout:
            self.has_root = True
            self.log("✓ Root access available", "SUCCESS")
            return True
        else:
            self.has_root = False
            self.log("✗ Root access NOT available", "WARNING")
            return False
    
    # ========================================================================
    # DEVICE INFORMATION
    # ========================================================================
    
    def acquire_device_info(self):
        """Get device information"""
        self.log("Acquiring device information...")
        
        props = {
            "android_version": "ro.build.version.release",
            "sdk_version": "ro.build.version.sdk",
            "manufacturer": "ro.product.manufacturer",
            "model": "ro.product.model",
            "device": "ro.product.device",
            "build_id": "ro.build.id",
            "serial": "ro.serialno",
            "security_patch": "ro.build.version.security_patch"
        }
        
        for key, prop in props.items():
            stdout, code = self._shell(f"getprop {prop}", as_root=False)
            if code == 0:
                self.device_info[key] = stdout.strip()
            else:
                self.device_info[key] = "Unknown"
        
        self.log(f"Device: {self.device_info.get('manufacturer')} {self.device_info.get('model')}")
        self.log(f"Android: {self.device_info.get('android_version')} (SDK {self.device_info.get('sdk_version')})")
    
    # ========================================================================
    # VOLATILE MEMORY ACQUISITION
    # ========================================================================
    
    def acquire_volatile_memory(self):
        """Acquire volatile memory artifacts"""
        if not Config.ACQUIRE_VOLATILE:
            return
            
        self.log("="*70)
        self.log("VOLATILE MEMORY ACQUISITION")
        self.log("="*70)
        
        # Get running processes
        stdout, code = self._shell("ps -A -o PID,USER,VSZ,NAME", as_root=False)
        
        if code == 0:
            processes = []
            for line in stdout.split('\n')[1:]:
                try:
                    parts = line.split()
                    if len(parts) >= 4:
                        processes.append(ProcessInfo(
                            pid=int(parts[0]),
                            name=parts[3] if len(parts) > 3 else parts[-1],
                            user=parts[1],
                            memory_kb=int(parts[2]) if parts[2].isdigit() else 0
                        ))
                except:
                    continue
            
            self.stats.processes_scanned = len(processes)
            self.log(f"Found {len(processes)} running processes")
            
            # Save process list
            processes.sort(key=lambda p: p.memory_kb, reverse=True)
            process_file = self.dirs["volatile"] / "process_list.txt"
            with open(process_file, 'w', encoding='utf-8') as f:
                f.write("RUNNING PROCESSES (Sorted by Memory Usage)\n")
                f.write("="*80 + "\n\n")
                f.write(f"{'PID':<8} {'USER':<15} {'MEM(KB)':<12} {'NAME':<40}\n")
                f.write("-"*80 + "\n")
                for p in processes:
                    f.write(f"{p.pid:<8} {p.user:<15} {p.memory_kb:<12} {p.name:<40}\n")
            
            self._add_to_stats("volatile", self._get_file_size_mb(process_file))
            
            # Acquire memory maps for top processes
            self.log("Acquiring memory maps for top 50 processes...")
            for idx, process in enumerate(processes[:50], 1):
                if idx % 10 == 0:
                    self.log(f"Progress: {idx}/50 processes")
                
                # Try with and without root
                for use_root in [self.has_root, False]:
                    stdout, code = self._shell(f"cat /proc/{process.pid}/maps 2>/dev/null", as_root=use_root)
                    
                    if code == 0 and stdout and len(stdout) > 100:
                        safe_name = self._sanitize_path(process.name)
                        safe_name = safe_name.replace('/', '_')[:50]  # Extra safety
                        
                        output_file = self.dirs["volatile"] / f"maps_{process.pid}_{safe_name}.txt"
                        
                        try:
                            with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                                f.write(f"# Process Memory Map\n")
                                f.write(f"# PID: {process.pid}\n")
                                f.write(f"# Name: {process.name}\n")
                                f.write(f"# User: {process.user}\n")
                                f.write(f"# Memory: {process.memory_kb} KB\n#\n")
                                f.write(stdout)
                            
                            self._add_to_stats("volatile", self._get_file_size_mb(output_file))
                            self.stats.memory_maps_acquired += 1
                            break  # Success, no need to retry
                        except Exception as e:
                            self.log(f"Failed to write map for PID {process.pid}: {e}", "WARNING")
                            continue
        
        # System memory info
        mem_info_file = self.dirs["volatile"] / "meminfo.txt"
        stdout, code = self._shell("cat /proc/meminfo", as_root=False)
        if code == 0 and stdout:
            with open(mem_info_file, 'w', encoding='utf-8') as f:
                f.write(stdout)
            self._add_to_stats("volatile", self._get_file_size_mb(mem_info_file))
        
        self.log(f"Volatile: {self.stats.volatile_mb:.2f} MB, {self.stats.memory_maps_acquired} memory maps")
    
    # ========================================================================
    # IMPROVED FILE EXTRACTION
    # ========================================================================
    
    def _extract_file_production(self, remote_path: str, local_base_dir: Path, 
                                 category: str = "app_data", flatten: bool = False) -> bool:
        """
        Production-ready file extraction with comprehensive error handling
        """
        try:
            # Skip if already extracted
            if remote_path in self.extracted_files:
                return False
            
            # Get filename
            filename = os.path.basename(remote_path)
            safe_filename = self._sanitize_path(filename)
            
            # Create local path
            if flatten:
                # Flat structure - just use filename
                local_file = local_base_dir / safe_filename
            else:
                # Preserve directory structure (sanitized)
                rel_path = self._sanitize_path(remote_path.lstrip('/'))
                local_file = local_base_dir / rel_path
            
            # Skip if exists
            if local_file.exists() and local_file.stat().st_size > 0:
                return False
            
            # Create parent directories
            try:
                local_file.parent.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                self.stats.path_errors += 1
                # Try flattened approach as fallback
                if not flatten:
                    return self._extract_file_production(remote_path, local_base_dir, category, flatten=True)
                return False
            
            success = False
            
            # Method 1: Direct pull (for accessible files)
            if not remote_path.startswith('/data/data/') and not remote_path.startswith('/data/user/'):
                stdout, code = self._adb(["pull", remote_path, str(local_file)], timeout=Config.PULL_TIMEOUT)
                if code == 0 and local_file.exists() and local_file.stat().st_size > 0:
                    success = True
            
            # Method 2: Root copy to temp location
            if not success and self.has_root:
                self.temp_counter += 1
                # Use simple temp filename to avoid path issues
                temp_name = f"amat_{self.temp_counter}_{hashlib.md5(filename.encode()).hexdigest()[:8]}.tmp"
                temp_path = f"/sdcard/Download/{temp_name}"
                
                # Copy with root
                self._shell(f"cp '{remote_path}' '{temp_path}'", as_root=True, timeout=30)
                self._shell(f"chmod 644 '{temp_path}'", as_root=True, timeout=5)
                
                # Pull from temp
                stdout, code = self._adb(["pull", temp_path, str(local_file)], timeout=Config.PULL_TIMEOUT)
                
                # Cleanup
                self._shell(f"rm '{temp_path}'", as_root=True, timeout=5)
                
                if code == 0 and local_file.exists() and local_file.stat().st_size > 0:
                    success = True
            
            # Method 3: Direct cat for small files
            if not success:
                # Check file size first
                size_out, _ = self._shell(f"stat -c %s '{remote_path}' 2>/dev/null", as_root=self.has_root)
                try:
                    file_size = int(size_out.strip())
                    if file_size > 0 and file_size < 5 * 1024 * 1024:  # < 5MB
                        stdout, code = self._shell(f"cat '{remote_path}' 2>/dev/null", 
                                                   as_root=self.has_root, timeout=30)
                        if code == 0 and stdout and len(stdout) > 0:
                            with open(local_file, 'w', encoding='utf-8', errors='replace') as f:
                                f.write(stdout)
                            if local_file.stat().st_size > 0:
                                success = True
                except:
                    pass
            
            # Verify success
            if success and local_file.exists():
                size_mb = self._get_file_size_mb(local_file)
                
                if size_mb == 0:
                    local_file.unlink()
                    return False
                
                if Config.MAX_FILE_SIZE_MB > 0 and size_mb > Config.MAX_FILE_SIZE_MB:
                    local_file.unlink()
                    self.log(f"Skipped large file ({size_mb:.1f}MB): {filename}", "DEBUG")
                    return False
                
                self._add_to_stats(category, size_mb)
                self.extracted_files.add(remote_path)
                
                # Track databases
                if remote_path.endswith(('.db', '.sqlite', '.db-wal', '.db-shm')):
                    self.stats.databases_acquired += 1
                
                return True
            else:
                self.stats.failed_files += 1
                return False
                
        except Exception as e:
            self.stats.extraction_errors += 1
            if Config.VERBOSE and self.stats.extraction_errors < 10:  # Limit error spam
                self.log(f"Extraction error: {filename}: {str(e)[:100]}", "DEBUG")
            return False
    
    # ========================================================================
    # APP DATA ACQUISITION
    # ========================================================================
    
    def acquire_app_data(self):
        """Acquire app data directories"""
        if not Config.ACQUIRE_APP_DATA:
            return
            
        self.log("="*70)
        self.log("APP DATA ACQUISITION")
        self.log("="*70)
        
        # Get installed packages
        stdout, code = self._shell("pm list packages", as_root=False)
        if code != 0:
            self.log("Failed to get package list", "ERROR")
            return
        
        packages = []
        for line in stdout.split('\n'):
            if line.startswith('package:'):
                pkg = line.replace('package:', '').strip()
                if pkg:
                    packages.append(pkg)
        
        self.log(f"Found {len(packages)} installed packages")
        
        for idx, package in enumerate(packages, 1):
            if idx % Config.SHOW_PROGRESS_EVERY == 0:
                self.log(f"Progress: {idx}/{len(packages)} apps, {self.stats.app_data_mb:.1f} MB, "
                        f"{self.stats.databases_acquired} DBs")
            
            self._acquire_app_directory(package)
            self.stats.apps_processed += 1
        
        self.log(f"App data: {self.stats.app_data_mb:.2f} MB from {self.stats.apps_processed} apps")
    
    def _acquire_app_directory(self, package: str):
        """Extract app directory"""
        safe_name = self._sanitize_path(package)[:100]  # Limit package name length
        local_app_dir = self.dirs["app_data"] / safe_name
        
        data_paths = [
            f"/data/data/{package}",
            f"/data/user/0/{package}"
        ]
        
        for base_path in data_paths:
            # Check existence
            stdout, code = self._shell(f"test -d {base_path} && echo EXISTS", as_root=self.has_root)
            if "EXISTS" not in stdout:
                continue
            
            # Get files (prioritize important ones)
            priority_patterns = [
                "-name '*.db' -o -name '*.sqlite'",
                "-name '*.xml' -o -name '*.json'",
                "-name 'shared_prefs' -type d"
            ]
            
            all_files = []
            
            # First get high-priority files
            for pattern in priority_patterns:
                cmd = f"find {base_path} -type f \\( {pattern} \\) 2>/dev/null | head -100"
                stdout, code = self._shell(cmd, as_root=self.has_root, timeout=Config.SHELL_TIMEOUT)
                
                if code == 0 and stdout.strip():
                    files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                    all_files.extend(files)
            
            # Then get other files
            if len(all_files) < Config.MAX_FILES_PER_APP:
                cmd = f"find {base_path} -type f 2>/dev/null | head -{Config.MAX_FILES_PER_APP}"
                stdout, code = self._shell(cmd, as_root=self.has_root, timeout=Config.SHELL_TIMEOUT)
                
                if code == 0 and stdout.strip():
                    files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                    all_files.extend(files)
            
            # Remove duplicates and extract
            all_files = list(set(all_files))[:Config.MAX_FILES_PER_APP]
            
            for file_path in all_files:
                self._extract_file_production(file_path, local_app_dir, "app_data")
            
            break  # Only process first valid path
    
    # ========================================================================
    # MEDIA ACQUISITION
    # ========================================================================
    
    def acquire_media(self):
        """Acquire media files"""
        if not Config.ACQUIRE_MEDIA:
            return
            
        self.log("="*70)
        self.log("MEDIA ACQUISITION")
        self.log("="*70)
        
        # Photos
        self.log("Acquiring photos...")
        photo_paths = [
            "/sdcard/DCIM",
            "/sdcard/Pictures",
            "/sdcard/Camera"
        ]
        
        photo_count = 0
        for path in photo_paths:
            cmd = f"find {path} -type f \\( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' \\) 2>/dev/null | head -500"
            stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
            
            if code == 0 and stdout.strip():
                files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                self.log(f"  Found {len(files)} photos in {path}")
                
                for idx, file_path in enumerate(files, 1):
                    if photo_count >= Config.MAX_MEDIA_FILES:
                        break
                    
                    if idx % 100 == 0:
                        self.log(f"  Photos: {idx}/{len(files)}")
                    
                    if self._extract_file_production(file_path, self.dirs["photos"], "media", flatten=True):
                        photo_count += 1
                        self.stats.photos_acquired += 1
        
        # Videos
        self.log("Acquiring videos...")
        video_paths = [
            "/sdcard/DCIM",
            "/sdcard/Movies",
            "/sdcard/Camera"
        ]
        
        video_count = 0
        for path in video_paths:
            cmd = f"find {path} -type f \\( -iname '*.mp4' -o -iname '*.3gp' -o -iname '*.avi' -o -iname '*.mkv' \\) 2>/dev/null | head -500"
            stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
            
            if code == 0 and stdout.strip():
                files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                self.log(f"  Found {len(files)} videos in {path}")
                
                for idx, file_path in enumerate(files, 1):
                    if video_count >= Config.MAX_MEDIA_FILES:
                        break
                    
                    if idx % 50 == 0:
                        self.log(f"  Videos: {idx}/{len(files)}")
                    
                    if self._extract_file_production(file_path, self.dirs["videos"], "media", flatten=True):
                        video_count += 1
                        self.stats.videos_acquired += 1
        
        # Audio
        self.log("Acquiring audio...")
        audio_paths = [
            "/sdcard/Music",
            "/sdcard/Recordings",
            "/sdcard/Notifications",
            "/sdcard/Ringtones"
        ]
        
        audio_count = 0
        for path in audio_paths:
            cmd = f"find {path} -type f \\( -iname '*.mp3' -o -iname '*.m4a' -o -iname '*.wav' -o -iname '*.ogg' \\) 2>/dev/null | head -200"
            stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
            
            if code == 0 and stdout.strip():
                files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                
                for file_path in files:
                    if self._extract_file_production(file_path, self.dirs["audio"], "media", flatten=True):
                        audio_count += 1
                        self.stats.audio_acquired += 1
        
        self.log(f"Media: {self.stats.media_mb:.2f} MB "
                f"({self.stats.photos_acquired} photos, {self.stats.videos_acquired} videos, "
                f"{self.stats.audio_acquired} audio)")
    
    # ========================================================================
    # DOCUMENTS & DOWNLOADS
    # ========================================================================
    
    def acquire_documents(self):
        """Acquire documents"""
        if not Config.ACQUIRE_DOCUMENTS:
            return
            
        self.log("="*70)
        self.log("DOCUMENTS ACQUISITION")
        self.log("="*70)
        
        doc_paths = [
            "/sdcard/Documents",
            "/sdcard/Download",
            "/sdcard"
        ]
        
        doc_extensions = "\\( -iname '*.pdf' -o -iname '*.doc' -o -iname '*.docx' -o " \
                        "-iname '*.xls' -o -iname '*.xlsx' -o -iname '*.ppt' -o " \
                        "-iname '*.pptx' -o -iname '*.txt' -o -iname '*.rtf' \\)"
        
        all_docs = set()
        
        for path in doc_paths:
            cmd = f"find {path} -maxdepth 3 -type f {doc_extensions} 2>/dev/null | head -300"
            stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
            
            if code == 0 and stdout.strip():
                files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                all_docs.update(files)
        
        if all_docs:
            self.log(f"Found {len(all_docs)} documents")
            
            for idx, file_path in enumerate(all_docs, 1):
                if idx % 50 == 0:
                    self.log(f"Progress: {idx}/{len(all_docs)}")
                
                if self._extract_file_production(file_path, self.dirs["documents"], "documents", flatten=True):
                    self.stats.documents_acquired += 1
        
        self.log(f"Documents: {self.stats.documents_acquired} files, {self.stats.documents_mb:.2f} MB")
    
    def acquire_downloads(self):
        """Acquire downloads folder"""
        if not Config.ACQUIRE_DOWNLOADS:
            return
            
        self.log("="*70)
        self.log("DOWNLOADS ACQUISITION")
        self.log("="*70)
        
        cmd = "find /sdcard/Download -type f 2>/dev/null | head -500"
        stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
        
        if code == 0 and stdout.strip():
            files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
            self.log(f"Found {len(files)} downloads")
            
            for idx, file_path in enumerate(files, 1):
                if idx % Config.SHOW_PROGRESS_EVERY == 0:
                    self.log(f"Progress: {idx}/{len(files)}")
                
                self._extract_file_production(file_path, self.dirs["downloads"], "downloads", flatten=True)
        
        self.log(f"Downloads: {self.stats.downloads_mb:.2f} MB")
    
    # ========================================================================
    # WHATSAPP
    # ========================================================================
    
    def acquire_whatsapp(self):
        """Acquire WhatsApp data"""
        if not Config.ACQUIRE_WHATSAPP:
            return
            
        self.log("="*70)
        self.log("WHATSAPP ACQUISITION")
        self.log("="*70)
        
        wa_packages = [
            "com.whatsapp",
            "com.whatsapp.w4b"  # WhatsApp Business
        ]
        
        total_files = 0
        
        for package in wa_packages:
            # App data
            if self.has_root:
                app_path = f"/data/data/{package}"
                stdout, code = self._shell(f"test -d {app_path} && echo EXISTS", as_root=True)
                
                if "EXISTS" in stdout:
                    self.log(f"Extracting {package} app data...")
                    
                    # Databases (highest priority)
                    cmd = f"find {app_path} -type f -name '*.db*' 2>/dev/null | head -50"
                    stdout, code = self._shell(cmd, as_root=True, timeout=Config.SHELL_TIMEOUT)
                    
                    if code == 0 and stdout.strip():
                        files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                        for file_path in files:
                            if self._extract_file_production(file_path, self.dirs["whatsapp"], "app_data"):
                                total_files += 1
            
            # SD card data
            sd_paths = [
                f"/sdcard/WhatsApp",
                f"/sdcard/Android/media/{package}"
            ]
            
            for sd_path in sd_paths:
                stdout, code = self._shell(f"test -d {sd_path} && echo EXISTS", as_root=False)
                
                if "EXISTS" in stdout:
                    self.log(f"Extracting WhatsApp from {sd_path}...")
                    
                    # Databases
                    cmd = f"find {sd_path} -type f -name '*.db*' 2>/dev/null | head -30"
                    stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
                    
                    if code == 0 and stdout.strip():
                        files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                        for file_path in files:
                            if self._extract_file_production(file_path, self.dirs["whatsapp"], "app_data"):
                                total_files += 1
                    
                    # Sample media (limited to avoid huge extractions)
                    media_dirs = ["Media/WhatsApp Images", "Media/WhatsApp Video"]
                    for media_dir in media_dirs:
                        cmd = f"find {sd_path}/{media_dir} -type f 2>/dev/null | head -20"
                        stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
                        
                        if code == 0 and stdout.strip():
                            files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                            for file_path in files:
                                if self._extract_file_production(file_path, self.dirs["whatsapp"], "app_data"):
                                    total_files += 1
        
        self.log(f"WhatsApp: {total_files} files extracted")
    
    # ========================================================================
    # BROWSER DATA
    # ========================================================================
    
    def acquire_browser_data(self):
        """Acquire browser data"""
        if not Config.ACQUIRE_BROWSER_DATA:
            return
            
        self.log("="*70)
        self.log("BROWSER DATA ACQUISITION")
        self.log("="*70)
        
        if not self.has_root:
            self.log("Browser data requires root access", "WARNING")
            return
        
        browsers = {
            "Chrome": "com.android.chrome",
            "Firefox": "org.mozilla.firefox",
            "Edge": "com.microsoft.emmx",
            "Samsung": "com.sec.android.app.sbrowser",
            "Opera": "com.opera.browser"
        }
        
        for browser_name, package in browsers.items():
            base_path = f"/data/data/{package}"
            stdout, code = self._shell(f"test -d {base_path} && echo EXISTS", as_root=True)
            
            if "EXISTS" not in stdout:
                continue
            
            self.log(f"Extracting {browser_name}...")
            browser_dir = self.dirs["browser"] / browser_name
            
            # Get databases and key files
            cmd = f"find {base_path} -type f \\( -name '*.db' -o -name 'Cookies' -o -name 'History' -o -name 'Bookmarks' \\) 2>/dev/null | head -50"
            stdout, code = self._shell(cmd, as_root=True, timeout=Config.SHELL_TIMEOUT)
            
            if code == 0 and stdout.strip():
                files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                for file_path in files:
                    self._extract_file_production(file_path, browser_dir, "app_data")
        
        self.log("Browser data acquisition complete")
    
    # ========================================================================
    # SYSTEM DATA
    # ========================================================================
    
    def acquire_system_data(self):
        """Acquire system logs and data"""
        if not Config.ACQUIRE_SYSTEM_LOGS:
            return
            
        self.log("="*70)
        self.log("SYSTEM DATA ACQUISITION")
        self.log("="*70)
        
        # System logs
        log_commands = {
            "logcat_main": ("logcat -d -v time", False),
            "logcat_system": ("logcat -b system -d -v time", False),
            "logcat_events": ("logcat -b events -d -v time", False),
            "dmesg": ("dmesg", self.has_root)
        }
        
        for name, (cmd, needs_root) in log_commands.items():
            if needs_root and not self.has_root:
                continue
            
            stdout, code = self._shell(cmd, as_root=needs_root, timeout=90)
            if code == 0 and stdout:
                log_file = self.dirs["system"] / f"{name}.txt"
                with open(log_file, 'w', encoding='utf-8', errors='replace') as f:
                    f.write(stdout)
                self._add_to_stats("system", self._get_file_size_mb(log_file))
        
        # Package info
        pkg_commands = {
            "installed_packages": "pm list packages -f",
            "disabled_packages": "pm list packages -d",
            "system_packages": "pm list packages -s",
            "third_party_packages": "pm list packages -3"
        }
        
        for name, cmd in pkg_commands.items():
            stdout, code = self._shell(cmd, as_root=False, timeout=30)
            if code == 0:
                pkg_file = self.dirs["system"] / f"{name}.txt"
                with open(pkg_file, 'w', encoding='utf-8') as f:
                    f.write(stdout)
                self._add_to_stats("system", self._get_file_size_mb(pkg_file))
        
        # System settings
        settings_file = self.dirs["system"] / "system_settings.txt"
        stdout, code = self._shell("settings list system && echo '---' && settings list secure && echo '---' && settings list global", 
                                   as_root=False, timeout=30)
        if code == 0:
            with open(settings_file, 'w', encoding='utf-8') as f:
                f.write(stdout)
            self._add_to_stats("system", self._get_file_size_mb(settings_file))
        
        # System databases (if root)
        if self.has_root:
            system_dbs = [
                "/data/system/users/0/accounts.db",
                "/data/system/users/0/settings_secure.db",
                "/data/system/users/0/settings_global.db",
                "/data/system/packages.xml"
            ]
            
            for db_path in system_dbs:
                self._extract_file_production(db_path, self.dirs["system"], "system", flatten=True)
        
        self.log(f"System data: {self.stats.system_mb:.2f} MB")
    
    # ========================================================================
    # REPORTS
    # ========================================================================
    
    def generate_reports(self):
        """Generate comprehensive reports"""
        self.log("="*70)
        self.log("GENERATING REPORTS")
        self.log("="*70)
        
        # Executive Summary
        summary_file = self.dirs["reports"] / "EXECUTIVE_SUMMARY.txt"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write(f"{Config.TOOL_NAME} v{Config.VERSION}\n")
            f.write("FORENSIC ACQUISITION REPORT\n")
            f.write("="*80 + "\n\n")
            
            f.write("DEVICE INFORMATION\n")
            f.write("-"*80 + "\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Device: {self.device_info.get('manufacturer')} {self.device_info.get('model')}\n")
            f.write(f"Android: {self.device_info.get('android_version')} (SDK {self.device_info.get('sdk_version')})\n")
            f.write(f"Security Patch: {self.device_info.get('security_patch')}\n")
            f.write(f"Build ID: {self.device_info.get('build_id')}\n")
            f.write(f"Root Access: {'YES' if self.has_root else 'NO'}\n\n")
            
            f.write("ACQUISITION SUMMARY\n")
            f.write("-"*80 + "\n")
            f.write(f"Total Data:      {self.stats.total_mb:>12.2f} MB ({self.stats.total_mb/1024:.2f} GB)\n")
            f.write(f"Total Files:     {self.stats.total_files:>12,}\n")
            f.write(f"Failed Files:    {self.stats.failed_files:>12,}\n")
            f.write(f"Path Errors:     {self.stats.path_errors:>12,}\n\n")
            
            f.write("DATA BREAKDOWN\n")
            f.write("-"*80 + "\n")
            f.write(f"Volatile Memory:     {self.stats.volatile_mb:>10.2f} MB\n")
            f.write(f"  Processes:         {self.stats.processes_scanned:>10}\n")
            f.write(f"  Memory Maps:       {self.stats.memory_maps_acquired:>10}\n\n")
            
            f.write(f"App Data:            {self.stats.app_data_mb:>10.2f} MB\n")
            f.write(f"  Apps:              {self.stats.apps_processed:>10}\n")
            f.write(f"  Databases:         {self.stats.databases_acquired:>10}\n\n")
            
            f.write(f"Media:               {self.stats.media_mb:>10.2f} MB\n")
            f.write(f"  Photos:            {self.stats.photos_acquired:>10}\n")
            f.write(f"  Videos:            {self.stats.videos_acquired:>10}\n")
            f.write(f"  Audio:             {self.stats.audio_acquired:>10}\n\n")
            
            f.write(f"Documents:           {self.stats.documents_mb:>10.2f} MB ({self.stats.documents_acquired} files)\n")
            f.write(f"Downloads:           {self.stats.downloads_mb:>10.2f} MB\n")
            f.write(f"System:              {self.stats.system_mb:>10.2f} MB\n\n")
            
            if not self.has_root:
                f.write("LIMITATIONS (NO ROOT ACCESS)\n")
                f.write("-"*80 + "\n")
                f.write("The following data may be incomplete:\n")
                f.write("  • Application internal data and databases\n")
                f.write("  • System databases and configuration\n")
                f.write("  • Browser history and cookies\n")
                f.write("  • Protected messaging app data\n\n")
            
            f.write("="*80 + "\n")
        
        # JSON log
        log_file = self.dirs["reports"] / "acquisition_log.json"
        
        # Convert stats to dict manually to avoid asdict issues
        stats_dict = {
            "volatile_mb": self.stats.volatile_mb,
            "app_data_mb": self.stats.app_data_mb,
            "media_mb": self.stats.media_mb,
            "documents_mb": self.stats.documents_mb,
            "downloads_mb": self.stats.downloads_mb,
            "system_mb": self.stats.system_mb,
            "total_mb": self.stats.total_mb,
            "processes_scanned": self.stats.processes_scanned,
            "memory_maps_acquired": self.stats.memory_maps_acquired,
            "apps_processed": self.stats.apps_processed,
            "databases_acquired": self.stats.databases_acquired,
            "photos_acquired": self.stats.photos_acquired,
            "videos_acquired": self.stats.videos_acquired,
            "audio_acquired": self.stats.audio_acquired,
            "documents_acquired": self.stats.documents_acquired,
            "total_files": self.stats.total_files,
            "failed_files": self.stats.failed_files,
            "path_errors": self.stats.path_errors,
            "extraction_errors": self.stats.extraction_errors
        }
        
        log_data = {
            "tool": f"{Config.TOOL_NAME} v{Config.VERSION}",
            "timestamp": datetime.datetime.now().isoformat(),
            "device_info": self.device_info,
            "root_access": self.has_root,
            "statistics": stats_dict,
            "configuration": {
                "max_file_size_mb": Config.MAX_FILE_SIZE_MB,
                "max_files_per_app": Config.MAX_FILES_PER_APP,
                "max_media_files": Config.MAX_MEDIA_FILES
            }
        }
        
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2)
        
        self.log("Reports generated")
    
    # ========================================================================
    # MAIN EXECUTION
    # ========================================================================
    
    def run_acquisition(self):
        """Execute forensic acquisition"""
        print("\n" + "="*80)
        print(f"  {Config.TOOL_NAME} v{Config.VERSION}")
        print("  Production-Ready Forensic Acquisition")
        print("="*80 + "\n")
        
        start_time = time.time()
        
        try:
            self.acquire_device_info()
            print()
            
            self.check_root_access()
            print()
            
            self.acquire_volatile_memory()
            print()
            
            self.acquire_app_data()
            print()
            
            self.acquire_media()
            print()
            
            self.acquire_documents()
            print()
            
            self.acquire_downloads()
            print()
            
            self.acquire_whatsapp()
            print()
            
            self.acquire_browser_data()
            print()
            
            self.acquire_system_data()
            print()
            
            self.generate_reports()
            print()
            
            elapsed = time.time() - start_time
            self._print_summary(elapsed)
            
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user")
            self.generate_reports()
        except Exception as e:
            print(f"\n[ERROR] {e}")
            import traceback
            traceback.print_exc()
            self.generate_reports()
    
    def _print_summary(self, elapsed: float):
        """Print final summary"""
        print("="*80)
        print("  ACQUISITION COMPLETE")
        print("="*80)
        print(f"\nOutput: {self.case_dir}")
        print(f"Time: {elapsed/60:.1f} minutes")
        print(f"\nData: {self.stats.total_mb:.2f} MB ({self.stats.total_mb/1024:.2f} GB)")
        print(f"Files: {self.stats.total_files:,}")
        print(f"Failed: {self.stats.failed_files:,}")
        print(f"Path Errors: {self.stats.path_errors:,}")
        
        print(f"\nBreakdown:")
        print(f"  Volatile:  {self.stats.volatile_mb:>8.2f} MB ({self.stats.memory_maps_acquired} maps)")
        print(f"  Apps:      {self.stats.app_data_mb:>8.2f} MB ({self.stats.databases_acquired} DBs)")
        print(f"  Media:     {self.stats.media_mb:>8.2f} MB ({self.stats.photos_acquired}P/{self.stats.videos_acquired}V/{self.stats.audio_acquired}A)")
        print(f"  Docs:      {self.stats.documents_mb:>8.2f} MB ({self.stats.documents_acquired} files)")
        print(f"  Downloads: {self.stats.downloads_mb:>8.2f} MB")
        print(f"  System:    {self.stats.system_mb:>8.2f} MB")
        
        print(f"\nReports:")
        print(f"  ✓ {self.dirs['reports'] / 'EXECUTIVE_SUMMARY.txt'}")
        print(f"  ✓ {self.dirs['reports'] / 'acquisition_log.json'}")
        print("="*80 + "\n")

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n" + "+"*80)
    print(f"{Config.TOOL_NAME} v{Config.VERSION}".center(80))
    print("Production Android Forensic Acquisition Tool".center(80))
    print("+"*80 + "\n")
    
    # Check ADB
    try:
        result = subprocess.run(["adb", "version"], capture_output=True, check=True, timeout=5)
        version = result.stdout.decode().split()[4]
        print(f"[✓] ADB: {version}")
    except:
        print("[✗] ERROR: ADB not found")
        sys.exit(1)
    
    # Detect device
    result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
    devices = [line.split()[0] for line in result.stdout.split('\n')[1:] if '\tdevice' in line]
    
    if not devices:
        print("[✗] ERROR: No device detected")
        sys.exit(1)
    
    device_id = devices[0] if len(devices) == 1 else None
    print(f"[✓] Device: {device_id}\n")
    
    print("FEATURES:")
    print("  • Windows path compatibility")
    print("  • Root detection with fallbacks")
    print("  • Multiple extraction methods")
    print("  • Comprehensive error handling")
    print("  • Detailed statistics and reports\n")
    
    response = input("Continue? (yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        sys.exit(0)
    print()
    
    # Run
    acq = ProductionForensicAcquisition(device_id=device_id)
    acq.run_acquisition()

if __name__ == "__main__":
    main()