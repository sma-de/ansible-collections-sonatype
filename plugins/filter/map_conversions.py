

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

import collections
import json

from ansible.errors import AnsibleFilterError, AnsibleOptionsError
from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils.common._collections_compat import MutableMapping
from ansible.module_utils._text import to_native

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META
from ansible_collections.smabot.base.plugins.module_utils.plugins.filter_base import FilterBase

from ansible.utils.display import Display


display = Display()


##
## Build final nexus user management module config from various sources
##
class CombineUserConfigFilter(FilterBase):

    FILTER_ID = 'combine_user_cfg'

    @property
    def argspec(self):
        tmp = super(CombineUserConfigFilter, self).argspec

        tmp.update({
          'password_map': ([collections.abc.Mapping, type(None)], None),
        })

        return tmp


    def run_specific(self, indict):
        if not isinstance(indict, MutableMapping):
            raise AnsibleOptionsError(
               "filter input must be a dictionary, but given value"\
               " '{}' has type '{}'".format(indict, type(indict))
            )

        ##display.vvv(
        ##   "[CombineUserConfigFilter.run_specific]: input"\
        ##   " map:\n{}".format(json.dumps(indict, indent=2))
        ##)

        pw_map = self.get_taskparam('password_map')

        if pw_map:
            ##display.vvv(
            ##   "[CombineUserConfigFilter.run_specific]: pw"\
            ##   " map:\n{}".format(json.dumps(pw_map, indent=2))
            ##)

            for k, v in indict.get('users', {}).items():
                upw = pw_map.get(v['id'], None)

                if not upw:
                    continue

                v['password'] = upw['password']

        ##display.vvv(
        ##   "[CombineUserConfigFilter.run_specific]: final"\
        ##   " pre return value:\n{}".format(json.dumps(indict, indent=2))
        ##)

        return indict


# ---- Ansible filters ----
class FilterModule(object):
    ''' generic dictionary filters '''

    def filters(self):
        res = {}

        tmp = [
          CombineUserConfigFilter,
        ]

        for f in tmp:
            res[f.FILTER_ID] = f()

        return res

