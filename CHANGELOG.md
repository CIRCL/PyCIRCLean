Changelog
=========

2.2.0 (in progress)
---
New features:
- Filecheck.py configuration information is now conveniently held in a Config
object instead of in globals
- New easier to read text-based logger (removed twiggy dependency)
- Various filetypes in filecheck.py now have improved descriptions for log
- Improved the interface for adding file descriptions to files

Fixes:
-


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
