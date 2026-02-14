# Contributing to AMAT

First off, thank you for considering contributing to AMAT! It's people like you that make AMAT such a great tool for the digital forensics community.

## Code of Conduct

This project and everyone participating in it is governed by our commitment to maintaining a respectful, professional environment. By participating, you are expected to uphold this standard.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

**Bug Report Template:**

```markdown
**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. Select option '...'
3. See error

**Expected behavior**
A clear description of what you expected to happen.

**Screenshots/Logs**
If applicable, add screenshots or log files.

**Environment:**
 - OS: [e.g. Windows 11]
 - Python Version: [e.g. 3.10.5]
 - ADB Version: [e.g. 1.0.41]
 - Android Version: [e.g. Android 13]
 - Root Access: [Yes/No]

**Additional context**
Any other context about the problem.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title** - Use a clear and descriptive title
- **Detailed description** - Provide a detailed description of the suggested enhancement
- **Use case** - Explain why this enhancement would be useful
- **Examples** - Provide specific examples if possible

### Pull Requests

1. **Fork the repo** and create your branch from `main`
2. **Make your changes** following the code standards below
3. **Test your changes** thoroughly
4. **Update documentation** if needed
5. **Write good commit messages** using conventional commits
6. **Submit a pull request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/AMAT.git
cd AMAT

# Create a branch
git checkout -b feature/amazing-feature

# Make your changes
# ...

# Test your changes
python amat_complete.py

# Commit using conventional commits
git commit -m "feat: add amazing feature"

# Push to your fork
git push origin feature/amazing-feature
```

## Code Standards

### Python Style Guide

- Follow **PEP 8** guidelines
- Use **4 spaces** for indentation (not tabs)
- Maximum line length: **88 characters** (Black formatter standard)
- Use **meaningful variable names**
- Add **docstrings** to all functions and classes

### Docstring Format

```python
def extract_contacts(self, database_path: str) -> List[Dict]:
    """
    Extract contacts from Android contacts database.
    
    Args:
        database_path: Absolute path to contacts2.db
        
    Returns:
        List of dictionaries containing contact information
        
    Raises:
        DatabaseError: If database cannot be opened
        
    Example:
        >>> contacts = extractor.extract_contacts("/path/to/contacts2.db")
        >>> print(contacts[0])
        {'name': 'John Doe', 'phone': '+1234567890'}
    """
    # Implementation
```

### Error Handling

Always use proper error handling:

```python
# ✅ Good
try:
    result = self._extract_file(file_path)
    if result:
        self.log(f"Extracted: {file_path}", "SUCCESS")
except FileNotFoundError:
    self.log(f"File not found: {file_path}", "WARNING")
except PermissionError:
    self.log(f"Permission denied: {file_path}", "ERROR")
except Exception as e:
    self.log(f"Unexpected error: {e}", "ERROR")

# ❌ Bad
try:
    result = self._extract_file(file_path)
except:
    pass  # Silent failure
```

### Commit Messages

We use **Conventional Commits** for clear commit history:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```bash
feat(acquisition): add support for Android 14
fix(database): handle corrupted SQLite databases
docs(readme): update installation instructions
refactor(analyzer): improve memory efficiency
```

## Testing

Before submitting a PR, ensure:

- [ ] Your code runs without errors
- [ ] All existing functionality still works
- [ ] You've tested on both rooted and non-rooted devices (if applicable)
- [ ] You've tested on Windows/macOS/Linux (if applicable)
- [ ] Documentation is updated

### Manual Testing Checklist

- [ ] Mode 1 (Acquisition Only) works
- [ ] Mode 2 (Analysis Only) works  
- [ ] Mode 3 (Quick Mode) works
- [ ] Database analysis functions correctly
- [ ] Contact extraction works
- [ ] SMS extraction works
- [ ] File search works
- [ ] Error handling works as expected

## Documentation

Update documentation for any user-facing changes:

- **README.md** - Update features, usage examples
- **Code comments** - Add inline comments for complex logic
- **Docstrings** - Update function/class docstrings
- **CHANGELOG.md** - Add entry for your changes

## Project Structure

```
AMAT/
├── amat_complete.py          # Main script (acquisition + analysis)
├── README.md                 # Project documentation
├── LICENSE                   # MIT License
├── CONTRIBUTING.md           # This file
├── CHANGELOG.md              # Version history
├── .gitignore               # Git ignore rules
├── docs/                    # Additional documentation
│   ├── INSTALLATION.md
│   ├── USAGE.md
│   └── API.md
├── examples/                # Example usage scripts
│   └── basic_workflow.py
└── tests/                   # Test files (future)
    └── test_acquisition.py
```

## Feature Priorities

Current priorities for contributions:

### High Priority
- [ ] Automated testing framework
- [ ] Support for Android 14+ features
- [ ] Enhanced WhatsApp encryption handling
- [ ] Cloud backup integration
- [ ] Multi-device parallel acquisition

### Medium Priority
- [ ] GUI interface
- [ ] Advanced filtering options
- [ ] Export to standard forensic formats (E01, AFF4)
- [ ] Timeline generation
- [ ] Artifact correlation

### Low Priority
- [ ] iOS support
- [ ] Remote acquisition capabilities
- [ ] Machine learning for artifact detection

## Questions?

Don't hesitate to ask questions:

- **GitHub Issues**: For technical questions
- **Discussions**: For general questions
- **Email**: For private inquiries

## Recognition

Contributors will be recognized in:
- README.md acknowledgments section
- CHANGELOG.md for their contributions
- GitHub contributors page

## Thank You!

Your contributions to open source make the digital forensics community stronger. Every contribution, no matter how small, is valued and appreciated.

---

**Happy Contributing! 🎉**
