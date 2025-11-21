from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="clay-sec-audit",
    version="1.0.0",
    author="Clay Security Team",
    description="Linux security auditor with auto-fix capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/clay/clay-sec-audit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "claysecaudit=src.cli.cli:main",
        ],
    },
)
