from setuptools import setup, find_packages

setup(
    name="eternal",
    version="3.0.0",
    py_modules=["manager_v2"],
    package_dir={"": "scripts"},
    install_requires=[
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "eternal=manager_v2:main",
        ],
    },
    author="Seed Plan",
    description="EternalCore: Generic Object Persistence Engine",
    python_requires=">=3.7",
)
