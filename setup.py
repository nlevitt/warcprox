#!/usr/bin/env python
# vim: set sw=4 et:

from setuptools.command.test import test as TestCommand
import sys
import setuptools 

# special class needs to be added to support the pytest written dump-anydbm tests
class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

deps = ['certauth>=1.1.0', 'warctools', 'kafka-python', 'surt==0.3b2', 'rethinkstuff']
try:
    import concurrent.futures
except:
    deps.append('futures')

setuptools.setup(name='warcprox',
        version='1.5.0',
        description='WARC writing MITM HTTP/S proxy',
        url='https://github.com/internetarchive/warcprox',
        author='Noah Levitt',
        author_email='nlevitt@archive.org',
        long_description=open('README.rst').read(),
        license='GPL',
        packages=['warcprox'],
        install_requires=deps,
        tests_require=['requests>=2.0.1', 'pytest'],  # >=2.0.1 for https://github.com/kennethreitz/requests/pull/1636
        cmdclass = {'test': PyTest},
        test_suite='warcprox.tests',
        scripts=['bin/dump-anydbm', 'bin/warcprox'],
        zip_safe=False,
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Environment :: Console',
            'License :: OSI Approved :: GNU General Public License (GPL)',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.4',
            'Topic :: Internet :: Proxy Servers',
            'Topic :: Internet :: WWW/HTTP',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: System :: Archiving',
        ])

