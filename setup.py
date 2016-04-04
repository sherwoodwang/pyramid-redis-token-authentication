#!/usr/bin/env python
import os

from setuptools import setup, find_packages

setup(name='pyramid_redis_token_authentication',
      version='0.1.3',
      description='Authenication policy for Pyramid which stores counterfoils of tokens in Redis',
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
          'pyramid',
          'redis',
          'zope.interface',
      ])
