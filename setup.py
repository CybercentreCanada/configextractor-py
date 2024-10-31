from setuptools import find_packages, setup

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    requirements = fh.readlines()

setup(
    name="configextractor-py",
    python_requires=">=3.8",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    description="A library for extracting malware configurations across multiple frameworks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=requirements,
    entry_points="""
    [console_scripts]
    cx=configextractor.cli:main
    configextractor=configextractor.cli:main
    """,
)
