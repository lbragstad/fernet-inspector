import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


HERE = os.path.dirname(__file__)


def read_requirements(filename):
    filename = os.path.join(HERE, filename)
    return [line.strip() for line in open(filename) if line.strip()]


setup(
    name='fernet_inspector',
    version='0.1.6',
    description='inspect fernet tokens generated by keystone',
    packages=['fernet_inspector'],
    entry_points={
        'console_scripts': [
            'fernet-inspector = fernet_inspector.cli:main'
        ]
    },
    long_description=open('README.rst').read(),
    author='Lance Bragstad',
    author_email='lbragstad@gmail.com',
    url='https://github.com/lbragstad/fernet-inspector',
    license='Apache Software License',
    install_requires=read_requirements('requirements.txt'),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Testing',
    ]
)
