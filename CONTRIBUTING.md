The issue tracker
=================

If you find a bug or see a problem with PyCIRCLean, please open an issue in the Github
repo. We'll do our best to respond as quickly as possible. Also, feel free to contribute a solution
to any of the open issues - we'll do our best to review your pull request in a timely manner.
This project is in active development, so any contributions are welcome!


Setting up a dev environment
============================

* First, you'll want to get a local copy of PyCIRCLean. If you'd like to make a pull request
with your changes at some point, you should fork the project on github, and then `git clone`
your fork.

* To install the project's dependencies, you can run `python setup.py install`. Alternatively,
you can use `pip install dev-requirements.txt` to ensure you download any testing dependencies as well.
We recommend that you use a virtualenv when installing dependencies. Note: python-magic has a non-Python
dependency, libmagic. It is typically included in Linux distributions, but you might have to install
it with homebrew (`brew install libmagic`) on macOS.

* Some of the example scripts have additional dependencies for handling various filetypes. You'll have to
install these seperately if you want to try out the examples or modify them for your own purposes.
Please open an issue if you have suggestions of good alternatives for the libraries we use for file handling
or if you have an example you'd like to contribute.


Running the tests
=================

* Running the tests is easy. First, make sure you've installed the project and testing dependencies.
Then, run `python -m pytest` or just `pytest` in the top level or /tests directory.
