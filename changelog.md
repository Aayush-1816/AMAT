# Changelog

All notable changes to the AMAT project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-13

### 🎉 Major Release - Complete Forensic Solution

**BREAKING CHANGES**: Complete rewrite combining acquisition and analysis in single tool.

### Added
- **Unified Framework**: Combined acquisition and analysis into single `amat_complete.py`
- **Three Operational Modes**:
  - Mode 1: Acquisition Only
  - Mode 2: Analysis Only  
  - Mode 3: Quick Mode (Acquire + Analyze)
- **Interactive Analysis Menu**: 9 analysis capabilities including:
  - Database discovery and deep inspection
  - Contact extraction
  - SMS/MMS message recovery
  - Package analysis
  - Keyword search across all files
- **Professional Reporting**: 
  - EXECUTIVE_SUMMARY.txt (human-readable)
  - acquisition_log.json (machine-readable)
- **Enhanced Documentation**:
  - Comprehensive README.md
  - Professional Word documentation (25+ pages)
  - Contributing guidelines
  - License information

### Changed
- Restructured code into modular architecture
- Improved error handling and retry logic
- Enhanced logging with timestamps and severity levels
- Better progress reporting during acquisition

### Fixed
- Windows path compatibility issues (colons, long paths)
- Memory map acquisition failures
- Database extraction errors
- File permission handling

### Technical Details
- **Lines of Code**: ~1,500
- **Functions**: 40+
- **Classes**: 2 (ForensicAcquisition, ForensicAnalyzer)
- **Supported Android**: 6.0+ (API 23+)
- **Platforms**: Windows, macOS, Linux

---

## [4.2.0] - 2026-02-10

### Production-Ready Release

### Added
- Windows path sanitization for cross-platform compatibility
- MD5 hash-based path shortening for long filenames
- Comprehensive error tracking and statistics
- Path error counter in reports

### Changed
- Improved file extraction with 3-tier strategy
- Enhanced retry logic (3 attempts per file)
- Better memory map acquisition (49/50 success rate)

### Fixed
- **Critical**: Windows MAX_PATH errors
- **Critical**: Invalid characters in filenames (colons, asterisks)
- Memory map extraction failures
- Long nested directory paths

### Performance
- Acquisition time: 8-9 minutes for 1.1 GB
- Success rate: 95%+ for accessible files
- Memory maps: 49/50 acquired successfully

---

## [4.1.0] - 2026-02-09

### Enhanced Extraction Release

### Added
- Root detection with automatic fallback
- Multiple extraction methods (pull, root copy, cat)
- Better file prioritization (databases first)
- Enhanced error handling

### Changed
- Increased extraction from 37 MB to 1.1 GB
- Improved app data acquisition

### Fixed
- Silent extraction failures
- Permission errors on app data
- Missing database files

### Known Issues
- Windows path errors (fixed in 4.2.0)
- Long path errors (fixed in 4.2.0)

---

## [4.0.0] - 2026-02-09

### Initial Production Release

### Added
- Complete volatile memory acquisition
- App data extraction (243 packages)
- Media files acquisition (photos, videos, audio)
- Documents and downloads
- WhatsApp data extraction
- Browser data (rooted devices)
- System logs and package information
- Professional reporting

### Features
- Automatic root detection
- Multi-category acquisition
- Timestamped case directories
- Comprehensive statistics

### Known Issues
- Low extraction volume (37 MB) - fixed in 4.1.0
- Permission failures - fixed in 4.1.0
- Silent errors - fixed in 4.1.0

---

## [3.x] - Development Versions

### Pre-release development
- Proof of concept implementations
- Feature testing
- Architecture experiments

---

## Roadmap

### [6.0.0] - Planned Features
- [ ] Automated testing framework
- [ ] GUI interface
- [ ] Android 14+ specific features
- [ ] Enhanced encryption handling
- [ ] Cloud backup integration
- [ ] Multi-device support

### [5.x] - Maintenance Releases
- [ ] Bug fixes and stability improvements
- [ ] Performance optimizations
- [ ] Documentation updates
- [ ] Community contributions

---

## Version Numbering

AMAT follows Semantic Versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes, major new features
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, minor improvements

---

## Upgrade Guide

### From 4.x to 5.0

**Breaking Changes:**
- Single script instead of separate acquisition/analysis tools
- New operational mode selection
- Changed command-line interface

**Migration Steps:**
1. Replace old scripts with `amat_complete.py`
2. Existing case directories remain compatible
3. Use Mode 2 to analyze old acquisitions
4. Update any automation scripts

**Benefits:**
- Unified workflow
- Interactive analysis
- Better error handling
- Professional reporting

---

## Support

For questions about specific versions:
- **Current version (5.0.0)**: Full support
- **Previous version (4.2.0)**: Security fixes only
- **Older versions**: Unsupported

---

## Contributors

### Version 5.0.0
- **Lead Developer**: Aayush Saxena
- **Documentation**: Aayush Saxena
- **Testing**: Community contributors

---

**Legend:**
- 🎉 Major release
- ✨ New feature
- 🐛 Bug fix
- 📚 Documentation
- ⚡ Performance improvement
- 🔒 Security fix
- ⚠️ Deprecation warning
- 💥 Breaking change
