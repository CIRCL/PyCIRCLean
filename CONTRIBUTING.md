The issue tracker
=================

If you find a bug or see a problem with PyCIRCLean, please open an issue in the Github
repo. We'll do our best to respond as quickly as possible. Also, feel free to contribute a solution
to any of the open issues - we'll do our best to review your pull request in a timely manner.
This project is in active development, so any contributions are welcome!


Setting up a dev environment
============================

* PyCIRCLean requires a working Python 3.3+ install. Before beginning install, it is recommended
to set up a virtualenv to contain Python dependencies. If you don't have experience managing Python virtualenvs,
[pyenv](https://github.com/pyenv/pyenv) and [pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv) are great
tools. If you're running MacOS or Windows and would like to contribute to filecheck.py, you will need access to a VM using
either a cloud service or something like Virtualbox.

* First, you'll want to get a local copy of PyCIRCLean. If you'd like to make a pull request
with your changes at some point, you should fork the project on github, and then `git clone`
your fork.

* To install the project's dependencies, you can run `python setup.py install`. Alternatively,
you can use `pip install dev-requirements.txt` to ensure you download any testing dependencies as well.
We recommend that you use a virtualenv when installing dependencies. Note: python-magic has a non-Python
dependency, libmagic. It is typically included in Linux distributions, but you might have to install
it with homebrew (`brew install libmagic`) on MacOS.

* To install the dependencies for filecheck.py on Linux, you can run `make install` or view the [Makefile](./Makefile) and
install the dependencies manually. Note that `pip install lxml` can only be run after `apt-get libxml2-dev`.


Running the tests
=================

* First, make sure you've installed the project and testing dependencies.
* Then, run `python -m pytest` or just `pytest` in the top level directory of the module.
* If you'd like to get information about code coverage, run the tests using
`pytest --cov=kittengroomer`.
* You can test with multiple versions of Python if you have them installed
by running `pip install tox` and then `tox`. Make sure you modify "envlist"
in tox.ini for the Python versions you plan to use.
