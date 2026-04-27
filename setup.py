#!/usr/bin/env python

from setuptools import Extension, find_packages, setup


setup(
    packages=find_packages(include=["rdpy", "rdpy.*"]),
    ext_modules=[Extension("rle", ["ext/rle.c"])],
)
