from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt', 'r') as fh:
    requirements = fh.readlines()

setup(
    name="configextractor-py",
    version="1.0.0",
    description="A library for extracting malware configurations for various malware families",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=requirements,
    entry_points="""
    [console_scripts]
    cx=configextractor.cli:main
    configextractor=configextractor.cli:main
    """
)
