from setuptools import setup, find_packages

setup(
    name="pyshield",
    version="0.1",
    packages=find_packages(),
    install_requires=["psutil", "requests"],
    entry_points={
        'console_scripts': [
            'pyshield=pyshield.cli:main',
        ],
    },
)