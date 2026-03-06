
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
          'admin_password': (list(string_types)),
          'admin_user': (list(string_types), 'admin'),
          'anonymous_access': ([bool], True),
        })

        return tmp


    def run_specific(self, result):
        admin_usr = self.get_taskparam('admin_user')
        admin_pw = self.get_taskparam('admin_password')
        ano_acc = self.get_taskparam('anonymous_access')

        ## check if server is currently in initial setup phase
        ##
        ## note: so far we dont know of real clean way of knowing
        ##   if nexus needs initial setup by querying anything of
        ##   its api, the best thing we can do so far is to use
        ##   eula accepted state and assume eula not being
        ##   accepted means initial setup phase, which is not
        ##   the worst approximation one can do
        ##
        eula_cfg = self.get_nexus_eula()
        do_setup = not eula_cfg['accepted']

        if do_setup:
            result['changed'] = True

            ## update admin account credentials
            self.update_nexus_user_password(admin_usr, admin_pw, 'default')

            if admin_usr == self.nexus_auth_user:
                self._api_pw_override = admin_pw

            result['admin_credentials'] = {
              'user': admin_usr, 'password': admin_pw,
            }

            ## update auth creds used here

            ## accept eula
            ##eula_cfg = self.get_nexus_eula()

            if not eula_cfg['accepted']:
                eula_cfg['accepted'] = True
                self.set_nexus_eula(eula_cfg)

            ## set anonymous_access
            ano_cfg = self.get_nexus_anonymous_access_settings()
            ano_cfg['enabled'] = ano_acc

            self.set_nexus_anonymous_access_settings(ano_cfg)

        return result

