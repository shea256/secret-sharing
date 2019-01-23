"""
Secret Sharing
==============

"""

from setuptools import setup

setup(
    name='nginsecretsharing',
    version='0.3.0',
    url='https://github.com/ginsburgnm/secret-sharing',
    license='MIT',
    author='nginsburg',
    author_email='ginsburgnm@gmail.com',
    description=("Tools for sharing secrets (like Bitcoin private keys), "
                 "using shamir's secret sharing scheme."),
    packages=[
        'nginsecretsharing',
    ],
    zip_safe=False,
    install_requires=[
        'six',
        'utilitybelt',
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
    ],
)
