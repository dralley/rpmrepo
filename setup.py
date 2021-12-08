from setuptools import setup, find_packages

with open("requirements.txt") as requirements:
    requirements = requirements.readlines()

setup(
    name="rpmrepo",
    version="0.1.0.dev5",
    description='A library and CLI tool providing facilities for working with RPM repositories.',
    author='Daniel Alley',
    license='GPLv2',
    python_requires=">=3.6",
    install_requires=requirements,
    packages=find_packages(exclude=["test"]),
    entry_points={
        'console_scripts': [
            'rpmrepo=rpmrepo.cli:cli',
        ],
    },
)
