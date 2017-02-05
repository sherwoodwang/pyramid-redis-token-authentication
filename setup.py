#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='pyramid_redis_token_authentication',
      version='0.2',
      description='Authentication policy for Pyramid which stores counterfoils of tokens in Redis',
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pyramid",
          "Topic :: Internet :: WWW/HTTP",
      ],
      author='Sherwood Wang',
      author_email='sherwood@wang.onl',
      url='https://github.com/sherwoodwang/pyramid-redis-token-authentication',
      packages=find_packages(),
      install_requires=[
          'pycrypto',
          'pyramid',
          'redis',
          'zope.interface',
      ])
