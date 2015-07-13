import os
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), 'README.txt')) as f:
    long_description = f.read()

setup(
    name="pyshark",
    version="0.3.6",
    packages=find_packages(),
    package_data={'': ['*.ini', '*.pcapng']},
    install_requires=['lxml', 'py', 'trollius', 'logbook'],
    tests_require=['mock', 'pytest'],
    url="https://github.com/KimiNewt/pyshark",
    long_description=long_description,
    author="KimiNewt",
    description="Python wrapper for tshark, allowing python packet parsing using wireshark dissectors",
    keywords="wireshark capture packets parsing packet",
    use_2to3=True,
)
