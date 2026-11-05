from setuptools import find_packages
from setuptools import setup

# Keep in step with certbot_dns_tropicalspace/__init__.py (a test
# checks it); snapcraft.yaml reads the version from here.
version = "1.0.0"

install_requires = [
    "acme>=3.1.0",
    "certbot>=3.1.0",
    "setuptools",
    "requests",
]

test_extras = [
    "pytest",
]

with open("README.md", encoding="utf-8") as readme:
    long_description = readme.read()

setup(
    name="certbot-dns-tropicalspace",
    version=version,
    description="tropicalspace.de DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fibreport/certbot-dns-tropicalspace",
    author="fibreport UG (haftungsbeschränkt)",
    author_email="rnd@fibreport.com",
    license="Apache License 2.0",
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        "test": test_extras,
    },
    entry_points={
        "certbot.plugins": [
            "dns-tropicalspace = "
            + "certbot_dns_tropicalspace.dns_tropicalspace:Authenticator"
        ]
    },
)
