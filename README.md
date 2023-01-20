# Authenticator service for SSDD lab

This project does not need to be installed

This repository contains the following files and directories:

- `configs` configuration files for authenticator service. IceStorm.TopicManager 
  and adminToken must be provided through "authenticator.config" file.
  If no Main service found this service will end.
- `Iceflix` is the main Python package.
  It contains the service file "Authenticator.py" the "IceFlix" inteface and "users.json"
  which will act as database.
- `iceflix/__init__.py` is an empty file needed by Python to
  recognise the `iceflix` directory as a Python module.
- `iceflix/Authenticator.py`: The service implemented, executed through `run_service`
- `iceflix/iceflix.ice` contains the Slice interface definition for the lab.
- `pyproject.toml` defines the build system used in the project.
- `run_service` You can run the authenticator service executing this file. For doing so,
  "bash run_service" command on your terminal. To stop the service press "Ctrl+C"
- `run_icestorm` Executing this file you set up the icestorm enviroment.
- `setup.cfg` is a Python distribution configuration file for Setuptools.
  It needs to be modified in order to adeccuate to the package name and
  console handler functions.
