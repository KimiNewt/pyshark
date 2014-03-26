from setuptools import setup, find_packages

with open('README.txt') as f:
    long_description = f.read()

setup(
    name = "pyshark",
    version = "0.2.2",
    packages = find_packages(),

    install_requires = ['lxml', 'py'],

    url = "https://github.com/KimiNewt/pyshark",
    long_description=long_description,
    author = "KimiNewt",
    description = "Python wrapper for tshark, allowing python packet parsing using wireshark dissectors",
    keywords = "wireshark capture packets parsing packet",
    use_2to3=True,
)
