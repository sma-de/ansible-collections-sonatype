
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


##import collections
##import copy
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
##   backend api call hanlding directly here
##
## TODO: convert to pylib based module
##
##

class ActionModule(NexusBase):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        tmp.update({
          ## TODO: license should be confidential param
          'license': (list(string_types), ''),
          'state': (list(string_types), 'present', ['present', 'absent']),

          'empty_okay': ([bool], False),
        })

        return tmp


    def run_specific(self, result):
        state = self.get_taskparam('state')
        empty_okay = self.get_taskparam('empty_okay')

        lic = self.get_taskparam('license')

        display.vv(
           "NEXUS_MANAGE_LICENSE :: get current license state"\
           " from server ..."
        )

        lic_pre = self.get_system_license()

        display.vvv(
           "NEXUS_MANAGE_LICENSE :: current server license state:\n{}".format(
              json.dumps(lic_pre or {}, indent=2)
           )
        )

        if state == 'present':
            if not lic:
                if not empty_okay:
                    result['failed'] = True
                    result['msg'] = "Trying to set or update product license"\
                       " but no license was provided as parameter,"\
                       " if this is an acceptable use case for you"\
                       " set optional flag 'empty_okay' to true"

                    return result

                ## no (potential new) license provided, this is a noop
                return result

            display.vv(
               "NEXUS_MANAGE_LICENSE :: apply given license"\
               " from server ..."
            )

            lic_post = self.set_system_license(lic)

            display.vvv(
               "NEXUS_MANAGE_LICENSE :: license state post update:\n{}".format(
                  json.dumps(lic_post, indent=2)
               )
            )

            result['licence_metadata'] = lic_post

            if lic_pre:
                display.vv(
                   "NEXUS_MANAGE_LICENSE :: check if license"\
                   " state has changed ..."
                )

                lic_diff = {}

                for k, v in lic_pre.items():
                    if v != lic_post[k]:
                        lic_diff[k] = {'before': v, 'after': lic_post[k]}

                if lic_diff:
                    result['changed'] = True
                    result['change_type'] = 'updated'
                    result['diff'] = lic_diff

            else:
                result['changed'] = True
                result['change_type'] = 'new'

        else: ## == absent
            if lic_pre:
                display.vv(
                   "NEXUS_MANAGE_LICENSE :: absenting currently set server"\
                   " license ..."
                )

                self.remove_system_licence()

                result['changed'] = True
                result['change_type'] = 'removed'
                result['diff'] = {'state': {
                  'before': 'present', 'after': 'absent'}
                }

            else:
                display.vv(
                   "NEXUS_MANAGE_LICENSE :: absenting license requested by"\
                   " caller but no license currently set on server ==> noop"
                )

        return result

