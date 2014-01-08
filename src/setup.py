from setuptools import setup, find_packages

setup(
    name = "pyshark",
    version = "0.1",
    packages = find_packages(),

    data_files = [('./pyshark', ['pyshark/config.ini'])],
    install_requires = ['lxml', 'py'],

    author = "Dor Green",
    author_email = "dorgreen1 at gmail dot com",
    description = "",
    keywords = "wireshark capture packets",
)