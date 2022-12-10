# Authenticator service for SSDD lab

This repository contains the following files and directories:

- `configs` configuration files for authenticator service. Main proxy 
  and adminToken must be provided through "authenticator.config" file.
  If Main service is off while running this service for the first time, it will end.
- `Iceflix` is the main Python package.
  It contains the service file "Authenticator.py" the "IceFlix" inteface and "users.json"
  which will act as a database.
- `iceflix/__init__.py` is an empty file needed by Python to
  recognise the `iceflix` directory as a Python module.
- `iceflix/cli.py` contains several functions to handle the basic console entry points
  defined in `python.cfg`.
- `iceflix/iceflix.ice` contains the Slice interface definition for the lab.
- `iceflix/main.py` has a minimal implementation of a service,
  without the service servant itself.
- `pyproject.toml` defines the build system used in the project.
- `run_service` You can run the authenticator service executing this file. For doing so,
  "bash run_service" command on your terminal. To stop the service press twice "Ctrl+C"
- `setup.cfg` is a Python distribution configuration file for Setuptools.
  It needs to be modified in order to adeccuate to the package name and
  console handler functions.
