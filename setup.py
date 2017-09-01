__author__ = "Christopher Bartz <bartz@dkrz.de>"
name = 's3auth'
entry_point = '%s.middleware:filter_factory' % (name)
version = '0.1'

from setuptools import setup, find_packages

setup(
    name=name,
    version=version,
    description='Openstack Swift Authentication system for s3.',
    license='Apache License (2.0)',
    author='Christopher Bartz',
    author_email='bartz@dkrz.de',
    packages=find_packages(),
    scripts=[
        'bin/s3auth-prep', 'bin/s3auth-list', 'bin/s3auth-add-key',
        'bin/s3auth-delete-key'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Environment :: No Input/Output (Daemon)'],
    entry_points={
        'paste.filter_factory': ['%s=%s' % (name, entry_point)]
    },
)
