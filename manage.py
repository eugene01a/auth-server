import os
import unittest
import coverage

from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

from auth.server import app, db
from auth.server.commands.init_db import InitDbCommand
from auth.server.commands.unit_cov import UnitCovCommand

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)
manager.add_command('init_db', InitDbCommand)
manager.add_command('unit_cov', UnitCovCommand)

@manager.command
def test():
    """Runs the unit tests without test coverage."""
    tests = unittest.TestLoader().discover('auth/tests', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    return 1

@manager.command
def create_db():
    """Creates the db tables."""
    db.create_all()

@manager.command
def drop_db():
    """Drops the db tables."""
    db.drop_all()


if __name__ == '__main__':
    manager.run()
