"""
Secret Sharing
==============

"""

from setuptools import setup

setup(
    name='secretsharing',
    version='0.1.4',
    url='https://github.com/halfmoonlabs/secretsharing',
    license='MIT',
    author='Halfmoon Labs',
    author_email='hello@halfmoon.io',
    description="Tools for sharing secrets, including shamir's secret sharing scheme.",
    packages=[
        'secretsharing',
    ],
    zip_safe=False,
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
)
