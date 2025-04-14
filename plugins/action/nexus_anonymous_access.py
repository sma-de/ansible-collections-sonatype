
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import collections
import copy
import json


from ansible.errors import AnsibleOptionsError
from ansible.module_utils.six import string_types
from ansible.utils.display import Display

from ansible_collections.smabot.sonatype.plugins.module_utils.plugins.nexus_action import NexusBase
from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import \
  merge_dicts, \
  setdefault_none

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert


display = Display()

##
## note: this would probably be better as module but currently we need
##   to be able to call other modules which is not possible from
##   inside a module atm (but fine for action plugins)
##
## note.2: currently there seems no senseable uptodate pylib for
##   backend handling, so in first iteration we will do heavy
##   backend api call handling directly here
##
## TODO: convert to pylib based module
##
##

class ActionModule(NexusBase):

    ##
    ## note: at least some realms have other "special" names for
    ##   anonymous setting not found anywhere else when dealing
    ##   with realms in the api
    ##
    ano_access_realm_mappings = {
        'default': 'NexusAuthorizingRealm',
    }


    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        tmp.update({
          'realm': (list(string_types),
              self.ano_access_realm_mappings['default']
          ),

          'user': (list(string_types), 'anonymous'),
          'state': (list(string_types), 'present', ['present', 'absent']),
        })

        return tmp


    @property
    def ano_access_realm_mappings_reversed(self):
        res = {}

        for k,v in self.ano_access_realm_mappings.items():
            res[v] = k

        return res


    def run_specific(self, result):
        realm = self.get_taskparam('realm')
        cfg_user = self.get_taskparam('user')
        state = self.get_taskparam('state')

        ## check if realm is valid
        normed_realm_ano = self.ano_access_realm_mappings.get(realm, None)\
                         or realm

        normed_realm_usrsrc = \
            self.ano_access_realm_mappings_reversed.get(realm, None) or realm

        self.check_user_source_valid(normed_realm_usrsrc)

        # pre-validate given user input, check if it is an existing
        # user for given realm
        self.check_nexus_user_valid(cfg_user, realm=normed_realm_usrsrc)

        new_settings = {
          'userId': cfg_user,
          'realmName': normed_realm_ano,
        }

        if state == 'present':
            new_settings['enabled'] = True
        elif state == 'absent':
            new_settings['enabled'] = False
        else:
            ansible_assert(False, "should never happen")

        ## query all existing users for given realm
        display.vv(
           "NEXUS_ANONYMOUS_ACCESS :: query existing anonymous access"\
           " settings from nexus ..."
        )

        cur_settings = self.get_nexus_anonymous_access_settings()

        display.vv(
           "NEXUS_ANONYMOUS_ACCESS :: current anonymous access"\
           " settings:\n{}".format(
              json.dumps(cur_settings, indent=2)
           )
        )

        if new_settings != cur_settings:
            display.vv(
               "NEXUS_ANONYMOUS_ACCESS :: new anonymous access"\
               " settings differ from current ones, update"\
               " needed:\n{}".format(
                  json.dumps(new_settings, indent=2)
               )
            )

            self.set_nexus_anonymous_access_settings(new_settings)
            result['changed'] = True

        else:
            display.vvv(
               "NEXUS_ANONYMOUS_ACCESS :: anonymous access"\
               " settings are already up to date: this is a noop"
            )

        result['old_settings'] = cur_settings
        result['new_settings'] = new_settings

        return result

