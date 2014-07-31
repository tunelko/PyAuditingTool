# -*- coding: utf-8 -*-
'''
@author: tunelko
'''
from threading import Lock

class Singleton(object):
    ''' Thread safe singleton '''

    def __init__(self, decorated):
        self._decorated = decorated
        self._instance_lock = Lock()

    def instance(self):
        '''
        Returns the singleton instance. Upon its first call, it creates a
        new instance of the decorated class and calls its `__init__` method.
        On all subsequent calls, the already created instance is returned.
        '''
        if not hasattr(self, "_instance"):
            with self._instance_lock:
                if not hasattr(self, "_instance"):
                    self._instance = self._decorated()
        return self._instance


    def __call__(self):
        raise TypeError(
            'Singletons must be accessed through the `instance` method.'
        )