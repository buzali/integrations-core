# (C) Datadog, Inc. 2020-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
try:
    from datadog_agent import read_persistent_cache, write_persistent_cache
except ImportError:

    def write_persistent_cache(key, value):
        pass

    def read_persistent_cache(key):
        return ''
