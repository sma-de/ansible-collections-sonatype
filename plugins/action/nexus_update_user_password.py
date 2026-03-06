
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
          'user': (list(string_types)),
          'password': (list(string_types)),
        })

        return tmp


    def run_specific(self, result):
        user = self.get_taskparam('user')
        pw = self.get_taskparam('password')

        self.update_nexus_user_password(user, pw, 'default')

        ## we obviously cannot really check if pw was
        ## changed or not, so we assume it did
        result['changed'] = True
        return result

