import os
import unittest

import coverage
from flask_script import Command

COV = coverage.coverage(
    branch=True,
    include='auth/*',
    omit=[
        'auth/tests/*',
        'auth/server/config.py',
        'auth/server/*/__init__.py'
    ]
)
COV.start()


class UnitCovCommand(Command):
    """Runs the unit tests with coverage."""

    def run(self):
        tests = unittest.TestLoader().discover('auth/server/tests')
        result = unittest.TextTestRunner(verbosity=2).run(tests)
        if result.wasSuccessful():
            COV.stop()
            COV.save()
            print('Coverage Summary:')
            COV.report()
            basedir = os.path.abspath(os.path.dirname(__file__))
            covdir = os.path.join(basedir, 'tmp/coverage')
            COV.html_report(directory=covdir)
            print('HTML version: file://%s/index.html' % covdir)
            COV.erase()
            return 0
        return 1
