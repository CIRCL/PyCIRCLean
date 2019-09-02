Changelog
=========

2.5
---

Fixes:
- Bump libraries, update code accordingly

2.4
---

Fixes:
- Add TOCTOU remediations

2.2.0
---
New features:
- Filecheck.py configuration information is now conveniently held in a Config
object instead of in globals
- New easier to read text-based logger (removed twiggy dependency)
- Various filetypes in filecheck.py now have improved descriptions for log
- Improved the PyCIRCLean API interface for adding file descriptions to files
- New integration test harness using a sample file catalog

Fixes:
- Switched back to released version of oletools
- Use set of malicious extensions from Chrome
- Check for XML Forms Architectures in PDFs
- Symlinks were being followed
- Prevent copying MacOS hidden files
- Fixes for several filetypes that were incorrectly being identified as dangerous
- Fix support for .rar archives
- Turn off executable bit on copied files


2.1.0
---

New features:
- Dropped Python 2.7 support: PyCIRCLean is now Python 3.3+ only
- Tests are now easier to write and run: we have support for pytest and tox!
- More documentation: both docstrings and more detailed readmes
- Added more types of examples for testing
- The Travis build now runs in ~10 minutes vs. ~30 minutes before


Fixes:
- Extension matching now catches lower/upper case errors
- Fixed remaining python 3 issues with filecheck.py
- Fixed support for .rtf files
- Many other small filetype related fixes
