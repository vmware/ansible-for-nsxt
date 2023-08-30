
from __future__ import print_function

import os
import sys
import glob

from setuptools import setup

ansible_path = "{}/site-packages/ansible".format(os.path.dirname(os.__file__))
ansible_rel_path = os.path.relpath(ansible_path, sys.prefix)

nsxt_modules = glob.glob('library/*.py')
nsxt_module_utils = glob.glob('module_utils/*.py')

setup(name='ansible-nsxt-modules',
      version='1.0.0',
      description='Ansible modules for VMware NSX-T',
      url='https://github.com/vmware/ansible-for-nsxt',
      author='VMware, Inc.',
      license='BSD 2-Clause or GPLv3',
      data_files=[
        ('{}/module_utils'.format(ansible_rel_path), nsxt_module_utils),
        ('{}/modules/network/nsxt'.format(ansible_rel_path), nsxt_modules)
      ],
      install_requires=[
        'pyvmomi',
        'pyvim',
        'requests',
        'ansible'
      ],
      classifiers=[
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)'
        'Programming Language :: Python',
      ]
      )
