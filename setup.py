import inspect
import os

from setuptools import setup

__location__ = os.path.join(os.getcwd(), os.path.dirname(inspect.getfile(inspect.currentframe())))


def get_install_requirements(path):
    with open(os.path.join(__location__, path), "r") as f:
        content = f.read()
        requires = [req for req in content.split("\\n") if req != ""]

    return requires


NAME = "github-repo-secrets-manager"
PROJECT_URLS = {
    "Bug Tracker": "https://github.com/rewindio/github-repo-secrets-manager/issues",
    "Source Code": "https://github.com/rewindio/github-repo-secrets-manager",
}
CLASSIFIERS = [
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: BSD License",
    "Operating System :: OS Independent",
    "Topic :: System :: Systems Administration",
]
INSTALL_REQUIRES = get_install_requirements("requirements.txt")
ENTRY_POINTS = {
    "console_scripts": [
        "github-secrets-manager=github_secrets_manager.cli:main"
    ],
}

setup(
    name=NAME,
    version="1.1.1",
    description="Manage github repo secrets using a common configuration file",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/rewindio/github-repo-secrets-manager",
    project_urls=PROJECT_URLS,
    author="DaveN",
    author_email="dave.north@rewind.io",
    classifiers=CLASSIFIERS,
    install_requires=INSTALL_REQUIRES,
    packages=["github_secrets_manager"],
    package_data={"": ["*"]},
    package_dir={"": "src"},
    entry_points=ENTRY_POINTS,
)
