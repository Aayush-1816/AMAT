#!/usr/bin/env python3
"""
AMAT - Android Memory Acquisition Tool
COMPLETE FORENSIC SOLUTION v1.0

Combines acquisition and analysis in a single tool:
- Full forensic data acquisition (rooted & non-rooted devices)
- Comprehensive data analysis and reporting
- Database extraction and parsing
- Interactive analysis interface

Author: Forensic Research Project
Version: 1.0 COMPLETE
License: Academic Use Only
"""

import subprocess
import hashlib
import os
import sys
import datetime
import json
import re
import time
import shutil
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, asdict

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    VERSION = "1.0"
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
    MAX_PATH_LENGTH = 200
    
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
    
    # Analysis settings
    MAX_DISPLAY_LINES = 100
    MAX_ANALYSIS_FILE_SIZE_MB = 50

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
# FORENSIC ACQUISITION ENGINE
# ============================================================================

class ForensicAcquisition:
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
        self.has_root = False
        self.temp_counter = 0
        
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
        """Sanitize path for Windows compatibility"""
        parts = path.split('/')
        sanitized_parts = []
        
        for part in parts:
            if not part:
                continue
            
            sanitized = part
            invalid_chars = [':', '*', '?', '"', '<', '>', '|', '\n', '\r', '\t']
            for char in invalid_chars:
                sanitized = sanitized.replace(char, '_')
            
            if sanitized.startswith('.'):
                sanitized = '_' + sanitized[1:]
            
            if len(sanitized) > 100:
                sanitized = sanitized[:100]
            
            sanitized_parts.append(sanitized)
        
        result = '/'.join(sanitized_parts)
        
        if len(result) > Config.MAX_PATH_LENGTH:
            hash_suffix = hashlib.md5(result.encode()).hexdigest()[:8]
            result = result[:Config.MAX_PATH_LENGTH-10] + '_' + hash_suffix
        
        return result
    
    def _adb(self, cmd: list, timeout: int = 30) -> Tuple[str, int]:
        """Execute ADB command"""
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
    
    def acquire_volatile_memory(self):
        """Acquire volatile memory artifacts"""
        if not Config.ACQUIRE_VOLATILE:
            return
            
        self.log("="*70)
        self.log("VOLATILE MEMORY ACQUISITION")
        self.log("="*70)
        
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
            
            self.log("Acquiring memory maps for top 50 processes...")
            for idx, process in enumerate(processes[:50], 1):
                if idx % 10 == 0:
                    self.log(f"Progress: {idx}/50 processes")
                
                for use_root in [self.has_root, False]:
                    stdout, code = self._shell(f"cat /proc/{process.pid}/maps 2>/dev/null", as_root=use_root)
                    
                    if code == 0 and stdout and len(stdout) > 100:
                        safe_name = self._sanitize_path(process.name)
                        safe_name = safe_name.replace('/', '_')[:50]
                        
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
                            break
                        except Exception as e:
                            continue
        
        mem_info_file = self.dirs["volatile"] / "meminfo.txt"
        stdout, code = self._shell("cat /proc/meminfo", as_root=False)
        if code == 0 and stdout:
            with open(mem_info_file, 'w', encoding='utf-8') as f:
                f.write(stdout)
            self._add_to_stats("volatile", self._get_file_size_mb(mem_info_file))
        
        self.log(f"Volatile: {self.stats.volatile_mb:.2f} MB, {self.stats.memory_maps_acquired} maps")
    
    def _extract_file_production(self, remote_path: str, local_base_dir: Path, 
                                 category: str = "app_data", flatten: bool = False) -> bool:
        """Production-ready file extraction"""
        try:
            if remote_path in self.extracted_files:
                return False
            
            filename = os.path.basename(remote_path)
            safe_filename = self._sanitize_path(filename)
            
            if flatten:
                local_file = local_base_dir / safe_filename
            else:
                rel_path = self._sanitize_path(remote_path.lstrip('/'))
                local_file = local_base_dir / rel_path
            
            if local_file.exists() and local_file.stat().st_size > 0:
                return False
            
            try:
                local_file.parent.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                self.stats.path_errors += 1
                if not flatten:
                    return self._extract_file_production(remote_path, local_base_dir, category, flatten=True)
                return False
            
            success = False
            
            if not remote_path.startswith('/data/data/') and not remote_path.startswith('/data/user/'):
                stdout, code = self._adb(["pull", remote_path, str(local_file)], timeout=Config.PULL_TIMEOUT)
                if code == 0 and local_file.exists() and local_file.stat().st_size > 0:
                    success = True
            
            if not success and self.has_root:
                self.temp_counter += 1
                temp_name = f"amat_{self.temp_counter}_{hashlib.md5(filename.encode()).hexdigest()[:8]}.tmp"
                temp_path = f"/sdcard/Download/{temp_name}"
                
                self._shell(f"cp '{remote_path}' '{temp_path}'", as_root=True, timeout=30)
                self._shell(f"chmod 644 '{temp_path}'", as_root=True, timeout=5)
                
                stdout, code = self._adb(["pull", temp_path, str(local_file)], timeout=Config.PULL_TIMEOUT)
                
                self._shell(f"rm '{temp_path}'", as_root=True, timeout=5)
                
                if code == 0 and local_file.exists() and local_file.stat().st_size > 0:
                    success = True
            
            if not success:
                size_out, _ = self._shell(f"stat -c %s '{remote_path}' 2>/dev/null", as_root=self.has_root)
                try:
                    file_size = int(size_out.strip())
                    if file_size > 0 and file_size < 5 * 1024 * 1024:
                        stdout, code = self._shell(f"cat '{remote_path}' 2>/dev/null", 
                                                   as_root=self.has_root, timeout=30)
                        if code == 0 and stdout and len(stdout) > 0:
                            with open(local_file, 'w', encoding='utf-8', errors='replace') as f:
                                f.write(stdout)
                            if local_file.stat().st_size > 0:
                                success = True
                except:
                    pass
            
            if success and local_file.exists():
                size_mb = self._get_file_size_mb(local_file)
                
                if size_mb == 0:
                    local_file.unlink()
                    return False
                
                if Config.MAX_FILE_SIZE_MB > 0 and size_mb > Config.MAX_FILE_SIZE_MB:
                    local_file.unlink()
                    return False
                
                self._add_to_stats(category, size_mb)
                self.extracted_files.add(remote_path)
                
                if remote_path.endswith(('.db', '.sqlite', '.db-wal', '.db-shm')):
                    self.stats.databases_acquired += 1
                
                return True
            else:
                self.stats.failed_files += 1
                return False
                
        except Exception as e:
            self.stats.extraction_errors += 1
            return False
    
    def acquire_app_data(self):
        """Acquire app data directories"""
        if not Config.ACQUIRE_APP_DATA:
            return
            
        self.log("="*70)
        self.log("APP DATA ACQUISITION")
        self.log("="*70)
        
        stdout, code = self._shell("pm list packages", as_root=False)
        if code != 0:
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
        safe_name = self._sanitize_path(package)[:100]
        local_app_dir = self.dirs["app_data"] / safe_name
        
        data_paths = [
            f"/data/data/{package}",
            f"/data/user/0/{package}"
        ]
        
        for base_path in data_paths:
            stdout, code = self._shell(f"test -d {base_path} && echo EXISTS", as_root=self.has_root)
            if "EXISTS" not in stdout:
                continue
            
            priority_patterns = [
                "-name '*.db' -o -name '*.sqlite'",
                "-name '*.xml' -o -name '*.json'"
            ]
            
            all_files = []
            
            for pattern in priority_patterns:
                cmd = f"find {base_path} -type f \\( {pattern} \\) 2>/dev/null | head -100"
                stdout, code = self._shell(cmd, as_root=self.has_root, timeout=Config.SHELL_TIMEOUT)
                
                if code == 0 and stdout.strip():
                    files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                    all_files.extend(files)
            
            if len(all_files) < Config.MAX_FILES_PER_APP:
                cmd = f"find {base_path} -type f 2>/dev/null | head -{Config.MAX_FILES_PER_APP}"
                stdout, code = self._shell(cmd, as_root=self.has_root, timeout=Config.SHELL_TIMEOUT)
                
                if code == 0 and stdout.strip():
                    files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                    all_files.extend(files)
            
            all_files = list(set(all_files))[:Config.MAX_FILES_PER_APP]
            
            for file_path in all_files:
                self._extract_file_production(file_path, local_app_dir, "app_data")
            
            break
    
    def acquire_media(self):
        """Acquire media files"""
        if not Config.ACQUIRE_MEDIA:
            return
            
        self.log("="*70)
        self.log("MEDIA ACQUISITION")
        self.log("="*70)
        
        self.log("Acquiring photos...")
        photo_paths = ["/sdcard/DCIM", "/sdcard/Pictures", "/sdcard/Camera"]
        
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
        
        self.log("Acquiring videos...")
        video_paths = ["/sdcard/DCIM", "/sdcard/Movies", "/sdcard/Camera"]
        
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
        
        self.log("Acquiring audio...")
        audio_paths = ["/sdcard/Music", "/sdcard/Recordings"]
        
        audio_count = 0
        for path in audio_paths:
            cmd = f"find {path} -type f \\( -iname '*.mp3' -o -iname '*.m4a' -o -iname '*.wav' \\) 2>/dev/null | head -200"
            stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
            
            if code == 0 and stdout.strip():
                files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                
                for file_path in files:
                    if self._extract_file_production(file_path, self.dirs["audio"], "media", flatten=True):
                        audio_count += 1
                        self.stats.audio_acquired += 1
        
        self.log(f"Media: {self.stats.media_mb:.2f} MB "
                f"({self.stats.photos_acquired}P/{self.stats.videos_acquired}V/{self.stats.audio_acquired}A)")
    
    def acquire_documents(self):
        """Acquire documents"""
        if not Config.ACQUIRE_DOCUMENTS:
            return
            
        self.log("="*70)
        self.log("DOCUMENTS ACQUISITION")
        self.log("="*70)
        
        doc_paths = ["/sdcard/Documents", "/sdcard/Download"]
        
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
    
    def acquire_whatsapp(self):
        """Acquire WhatsApp data"""
        if not Config.ACQUIRE_WHATSAPP:
            return
            
        self.log("="*70)
        self.log("WHATSAPP ACQUISITION")
        self.log("="*70)
        
        wa_packages = ["com.whatsapp", "com.whatsapp.w4b"]
        
        total_files = 0
        
        for package in wa_packages:
            if self.has_root:
                app_path = f"/data/data/{package}"
                stdout, code = self._shell(f"test -d {app_path} && echo EXISTS", as_root=True)
                
                if "EXISTS" in stdout:
                    self.log(f"Extracting {package} app data...")
                    
                    cmd = f"find {app_path} -type f -name '*.db*' 2>/dev/null | head -50"
                    stdout, code = self._shell(cmd, as_root=True, timeout=Config.SHELL_TIMEOUT)
                    
                    if code == 0 and stdout.strip():
                        files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                        for file_path in files:
                            if self._extract_file_production(file_path, self.dirs["whatsapp"], "app_data"):
                                total_files += 1
            
            sd_paths = [f"/sdcard/WhatsApp", f"/sdcard/Android/media/{package}"]
            
            for sd_path in sd_paths:
                stdout, code = self._shell(f"test -d {sd_path} && echo EXISTS", as_root=False)
                
                if "EXISTS" in stdout:
                    self.log(f"Extracting WhatsApp from {sd_path}...")
                    
                    cmd = f"find {sd_path} -type f -name '*.db*' 2>/dev/null | head -30"
                    stdout, code = self._shell(cmd, as_root=False, timeout=Config.SHELL_TIMEOUT)
                    
                    if code == 0 and stdout.strip():
                        files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                        for file_path in files:
                            if self._extract_file_production(file_path, self.dirs["whatsapp"], "app_data"):
                                total_files += 1
        
        self.log(f"WhatsApp: {total_files} files extracted")
    
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
            "Samsung": "com.sec.android.app.sbrowser"
        }
        
        for browser_name, package in browsers.items():
            base_path = f"/data/data/{package}"
            stdout, code = self._shell(f"test -d {base_path} && echo EXISTS", as_root=True)
            
            if "EXISTS" not in stdout:
                continue
            
            self.log(f"Extracting {browser_name}...")
            browser_dir = self.dirs["browser"] / browser_name
            
            cmd = f"find {base_path} -type f \\( -name '*.db' -o -name 'Cookies' -o -name 'History' \\) 2>/dev/null | head -50"
            stdout, code = self._shell(cmd, as_root=True, timeout=Config.SHELL_TIMEOUT)
            
            if code == 0 and stdout.strip():
                files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
                for file_path in files:
                    self._extract_file_production(file_path, browser_dir, "app_data")
        
        self.log("Browser data acquisition complete")
    
    def acquire_system_data(self):
        """Acquire system logs and data"""
        if not Config.ACQUIRE_SYSTEM_LOGS:
            return
            
        self.log("="*70)
        self.log("SYSTEM DATA ACQUISITION")
        self.log("="*70)
        
        log_commands = {
            "logcat_main": ("logcat -d -v time", False, 90),
            "logcat_system": ("logcat -b system -d -v time", False, 90),
            "logcat_events": ("logcat -b events -d -v time", False, 60),
            "dmesg": ("dmesg", self.has_root, 30)
        }
        
        for name, (cmd, needs_root, timeout) in log_commands.items():
            if needs_root and not self.has_root:
                continue
            
            stdout, code = self._shell(cmd, as_root=needs_root, timeout=timeout)
            if code == 0 and stdout:
                log_file = self.dirs["system"] / f"{name}.txt"
                with open(log_file, 'w', encoding='utf-8', errors='replace') as f:
                    f.write(stdout)
                
                size_mb = self._get_file_size_mb(log_file)
                self._add_to_stats("system", size_mb)
        
        pkg_commands = {
            "packages_all": "pm list packages -f",
            "packages_disabled": "pm list packages -d",
            "packages_system": "pm list packages -s",
            "packages_third_party": "pm list packages -3"
        }
        
        for name, cmd in pkg_commands.items():
            stdout, code = self._shell(cmd, as_root=False, timeout=30)
            if code == 0:
                pkg_file = self.dirs["system"] / f"{name}.txt"
                with open(pkg_file, 'w', encoding='utf-8') as f:
                    f.write(stdout)
                
                size_mb = self._get_file_size_mb(pkg_file)
                self._add_to_stats("system", size_mb)
        
        settings_commands = {
            "settings_system": "settings list system",
            "settings_secure": "settings list secure",
            "settings_global": "settings list global"
        }
        
        for name, cmd in settings_commands.items():
            stdout, code = self._shell(cmd, as_root=False, timeout=30)
            if code == 0:
                settings_file = self.dirs["system"] / f"{name}.txt"
                with open(settings_file, 'w', encoding='utf-8') as f:
                    f.write(stdout)
                
                size_mb = self._get_file_size_mb(settings_file)
                self._add_to_stats("system", size_mb)
        
        if self.has_root:
            system_dbs = [
                "/data/system/users/0/accounts.db",
                "/data/system/users/0/settings_secure.db",
                "/data/system/packages.xml"
            ]
            
            for db_path in system_dbs:
                self._extract_file_production(db_path, self.dirs["system"], "system", flatten=True)
        
        self.log(f"System data: {self.stats.system_mb:.2f} MB")
    
    def generate_reports(self):
        """Generate comprehensive reports"""
        self.log("="*70)
        self.log("GENERATING REPORTS")
        self.log("="*70)
        
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
        
        # JSON log with manual dict conversion
        log_file = self.dirs["reports"] / "acquisition_log.json"
        
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
            "statistics": stats_dict
        }
        
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2)
        
        self.log("Reports generated")
    
    def run_acquisition(self):
        """Execute forensic acquisition"""
        print("\n" + "="*80)
        print(f"  {Config.TOOL_NAME} v{Config.VERSION}")
        print("  Complete Forensic Solution - Acquisition Module")
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
            
            return self.case_dir
            
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user")
            self.generate_reports()
            return self.case_dir
        except Exception as e:
            print(f"\n[ERROR] {e}")
            import traceback
            traceback.print_exc()
            self.generate_reports()
            return self.case_dir
    
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
# FORENSIC ANALYZER
# ============================================================================

class ForensicAnalyzer:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        
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
    
    def print_overview(self):
        """Print case overview"""
        print("\n" + "="*80)
        print("FORENSIC CASE ANALYSIS")
        print("="*80)
        print(f"\nCase Directory: {self.case_dir}")
        print(f"Case ID: {self.case_dir.name}")
        
        summary_file = self.dirs["reports"] / "EXECUTIVE_SUMMARY.txt"
        if summary_file.exists():
            print("\n" + "-"*80)
            print("EXECUTIVE SUMMARY")
            print("-"*80)
            with open(summary_file, 'r', encoding='utf-8') as f:
                content = f.read()
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
    
    def analyze_volatile_memory(self):
        """Analyze volatile memory artifacts"""
        print("\n" + "="*80)
        print("VOLATILE MEMORY ANALYSIS")
        print("="*80)
        
        volatile_dir = self.dirs["volatile"]
        
        process_file = volatile_dir / "process_list.txt"
        if process_file.exists():
            print("\nPROCESS LIST:")
            print("-"*80)
            with open(process_file, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')[:30]
                print('\n'.join(lines))
        
        map_files = list(volatile_dir.glob("maps_*.txt"))
        if map_files:
            print(f"\n\nMEMORY MAPS: Found {len(map_files)} memory maps")
            print("-"*80)
            print("Sample maps (first 5):")
            
            for idx, map_file in enumerate(sorted(map_files)[:5], 1):
                print(f"\n{idx}. {map_file.name}")
                with open(map_file, 'r', encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()[:15]
                    print(''.join(lines))
        
        meminfo = volatile_dir / "meminfo.txt"
        if meminfo.exists():
            print("\n\nSYSTEM MEMORY INFO:")
            print("-"*80)
            with open(meminfo, 'r', encoding='utf-8') as f:
                lines = f.readlines()[:20]
                print(''.join(lines))
    
    def find_databases(self):
        """Find all SQLite databases"""
        print("\n" + "="*80)
        print("DATABASE DISCOVERY")
        print("="*80)
        
        db_extensions = ['.db', '.sqlite']
        databases = []
        
        app_data_dir = self.dirs["app_data"]
        if app_data_dir.exists():
            for ext in db_extensions:
                databases.extend(app_data_dir.rglob(f"*{ext}"))
        
        print(f"\nFound {len(databases)} databases:\n")
        
        categorized = {}
        for db in databases:
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
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            print(f"\nTables: {len(tables)}")
            print("-"*80)
            
            for table_name, in tables:
                print(f"\nTable: {table_name}")
                
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                    count = cursor.fetchone()[0]
                    print(f"  Rows: {count}")
                except:
                    print(f"  Rows: [Unable to count]")
                
                try:
                    cursor.execute(f"PRAGMA table_info('{table_name}')")
                    columns = cursor.fetchall()
                    print(f"  Columns: {', '.join([col[1] for col in columns])}")
                except:
                    print(f"  Columns: [Unable to retrieve]")
                
                try:
                    cursor.execute(f"SELECT * FROM '{table_name}' LIMIT 3")
                    rows = cursor.fetchall()
                    
                    if rows:
                        print(f"  Sample data:")
                        for row in rows:
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
    
    def extract_contacts(self):
        """Extract contacts from contacts database"""
        print("\n" + "="*80)
        print("CONTACTS EXTRACTION")
        print("="*80)
        
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
                
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='data';")
                if not cursor.fetchone():
                    print("  No 'data' table found")
                    continue
                
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
    
    def extract_sms(self):
        """Extract SMS messages"""
        print("\n" + "="*80)
        print("SMS MESSAGES EXTRACTION")
        print("="*80)
        
        sms_db = self.case_dir / "02_APP_DATA" / "com.android.providers.telephony" / "data" / "data" / \
                 "com.android.providers.telephony" / "databases" / "mmssms.db"
        
        if not sms_db.exists():
            print("\nNo SMS database found")
            return
        
        print(f"\nAnalyzing: {sms_db.name}")
        
        try:
            conn = sqlite3.connect(str(sms_db))
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM sms")
            count = cursor.fetchone()[0]
            
            print(f"\nTotal SMS messages: {count}")
            
            if count > 0:
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
                    try:
                        dt = datetime.datetime.fromtimestamp(int(date) / 1000)
                        date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        date_str = str(date)
                    
                    msg_type_str = "Received" if msg_type == 1 else "Sent"
                    
                    if body and len(body) > 100:
                        body = body[:100] + "..."
                    
                    print(f"\n{idx}. [{date_str}] {msg_type_str}")
                    print(f"   From/To: {address}")
                    print(f"   Message: {body}")
            
            conn.close()
            
        except Exception as e:
            print(f"\nError: {e}")
    
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
        
        system_pkgs = [p for p in packages if p[0].startswith('com.android.') or p[0].startswith('android.')]
        third_party = [p for p in packages if p not in system_pkgs]
        
        print(f"System packages: {len(system_pkgs)}")
        print(f"Third-party apps: {len(third_party)}")
        
        print("\nThird-party applications:")
        print("-"*80)
        
        for name, path in sorted(third_party):
            print(f"  {name}")
    
    def search_files(self, search_term: str):
        """Search for term across all text files"""
        print("\n" + "="*80)
        print(f"SEARCHING FOR: '{search_term}'")
        print("="*80)
        
        results = []
        
        for root, dirs, files in os.walk(self.case_dir):
            for filename in files:
                if filename.endswith(('.txt', '.json', '.xml', '.log')):
                    filepath = Path(root) / filename
                    
                    if filepath.stat().st_size > Config.MAX_ANALYSIS_FILE_SIZE_MB * 1024 * 1024:
                        continue
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                            content = f.read()
                            
                            if search_term.lower() in content.lower():
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
                
                for line_num, line in matching_lines[:5]:
                    if len(line) > 100:
                        line = line[:100] + "..."
                    print(f"  Line {line_num}: {line}")
                
                if len(matching_lines) > 5:
                    print(f"  ... and {len(matching_lines) - 5} more matches")
        else:
            print("\nNo results found")
    
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
            print("8.  Analyze Installed Packages")
            print("9.  Search Files")
            print("0.  Exit")
            
            choice = input("\nEnter choice: ").strip()
            
            if choice == '0':
                print("\nExiting analyzer...")
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
                self.analyze_packages()
            elif choice == '9':
                term = input("Enter search term: ").strip()
                if term:
                    self.search_files(term)
            else:
                print("Invalid choice")
            
            input("\nPress Enter to continue...")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    print("\n" + "="*80)
    print(f"  {Config.TOOL_NAME} v{Config.VERSION}".center(80))
    print("  Complete Android Forensic Solution".center(80))
    print("  Acquisition + Analysis in One Tool".center(80))
    print("="*80 + "\n")
    
    print("MAIN MENU:")
    print("1. Acquire Data from Device (Forensic Acquisition)")
    print("2. Analyze Existing Case (Forensic Analysis)")
    print("3. Quick Mode (Acquire + Analyze)")
    print("0. Exit")
    
    main_choice = input("\nEnter choice: ").strip()
    
    if main_choice == '0':
        print("\nExiting...")
        sys.exit(0)
    
    elif main_choice == '1':
        # ACQUISITION MODE
        print("\n" + "="*80)
        print("FORENSIC ACQUISITION MODE")
        print("="*80 + "\n")
        
        # Check ADB
        try:
            result = subprocess.run(["adb", "version"], capture_output=True, check=True, timeout=5, text=True)
            version = result.stdout.split()[4]
            print(f"[✓] ADB: {version}")
        except:
            print("[✗] ERROR: ADB not found")
            sys.exit(1)
        
        # Detect devices
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        devices = [line.split()[0] for line in result.stdout.split('\n')[1:] if '\tdevice' in line]
        
        if not devices:
            print("[✗] ERROR: No device detected")
            sys.exit(1)
        
        device_id = devices[0] if len(devices) == 1 else None
        print(f"[✓] Device: {device_id}\n")
        
        response = input("Start acquisition? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            sys.exit(0)
        
        # Run acquisition
        acq = ForensicAcquisition(device_id=device_id)
        case_dir = acq.run_acquisition()
        
        # Ask if user wants to analyze
        print("\n" + "="*80)
        response = input("Analyze acquired data now? (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            analyzer = ForensicAnalyzer(case_dir)
            analyzer.interactive_menu()
    
    elif main_choice == '2':
        # ANALYSIS MODE
        print("\n" + "="*80)
        print("FORENSIC ANALYSIS MODE")
        print("="*80 + "\n")
        
        case_dir = input("Enter case directory path: ").strip()
        
        if not case_dir:
            print("Error: No case directory specified")
            sys.exit(1)
        
        try:
            analyzer = ForensicAnalyzer(Path(case_dir))
            analyzer.interactive_menu()
        except Exception as e:
            print(f"\nError: {e}")
            import traceback
            traceback.print_exc()
    
    elif main_choice == '3':
        # QUICK MODE - Acquire then analyze
        print("\n" + "="*80)
        print("QUICK MODE - ACQUIRE + ANALYZE")
        print("="*80 + "\n")
        
        # Check ADB
        try:
            result = subprocess.run(["adb", "version"], capture_output=True, check=True, timeout=5, text=True)
        except:
            print("[✗] ERROR: ADB not found")
            sys.exit(1)
        
        # Detect devices
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        devices = [line.split()[0] for line in result.stdout.split('\n')[1:] if '\tdevice' in line]
        
        if not devices:
            print("[✗] ERROR: No device detected")
            sys.exit(1)
        
        device_id = devices[0]
        
        # Acquire
        acq = ForensicAcquisition(device_id=device_id)
        case_dir = acq.run_acquisition()
        
        # Analyze
        print("\n" + "="*80)
        print("STARTING ANALYSIS...")
        print("="*80)
        
        analyzer = ForensicAnalyzer(case_dir)
        analyzer.interactive_menu()
    
    else:
        print("Invalid choice")

if __name__ == "__main__":

    main()
