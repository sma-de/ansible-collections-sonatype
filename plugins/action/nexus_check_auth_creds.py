
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import collections
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


class ActionModule(NexusBase):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        tmp.update({
          ## TODO: test_creds should be marked as confidential param
          'test_creds': ([collections.abc.Mapping], {}),
          'check_default_creds': ([bool], True),

          'check_mode': (list(string_types),
             'first_okay', ['first_okay', 'all']
          ),

          'error_mode': (list(string_types),
             ##'any', ['any', 'all']
             'all', ['any', 'all']
          ),
        })

        return tmp


    def _run_login_test(self, result, state_map, lgid, user, pw, **lg_kwargs):
        lg_kwargs['raise_error'] = False
        testres = self.test_nexus_user_login(user, pw, **lg_kwargs)

        if testres:
            state_map['okay'][lgid] = {
              'user': user,
              'password': pw,
              'is_default': user is None,
            }

        else:
            state_map['failed'][lgid] = {
              'user': user,
              'is_default': user is None,
            }

        return self._handle_modes(state_map, result)


    def _handle_modes(self, state_map, result):
        check_mode = self.get_taskparam('check_mode')
        err_mode = self.get_taskparam('error_mode')

        if err_mode == 'any' and state_map['failed']:
            result['failed'] = True
            result['error_reason'] = \
               "module was set to fail when one of the credential sets"\
               " to test failed and at least one did fail"

            return True

        if check_mode == 'first_okay' and state_map['okay']:
            return True

        return False


    def _finish_run(self, state_map, result):
        result['check_state'] = state_map

        if result.get('failed', False):
            return result

        okay_creds = state_map['okay']

        if not okay_creds:
            result['failed'] = True
            result['error_reason'] = \
              "none of the tested credential sets are valid"

            return result

        ## make additional "short cut access point"
        ## for one (first) valid cred set
        result['valid_creds'] = next(iter(okay_creds.values()))
        return result


    def run_specific(self, result):
        do_defcreds = self.get_taskparam('check_default_creds')
        test_creds = self.get_taskparam('test_creds')

        ansible_assert(do_defcreds or test_creds,
          "Given module params make no sense as neither default"\
          " credentials should be tested, nor are extra credentials"\
          " to test are given meaning this module does basically nothing"
        )

        state_map = {
          'okay': {},
          'failed': {},
        }

        if do_defcreds:
            ## first test if default / env auth creds are
            ## working if not explicitly disabled
            display.vv(
               "NEXUS_CHECK_AUTH_CREDS :: test default auth"\
               " credentials from env ..."
            )

            try:
                if self._run_login_test(result, state_map,
                    'default', None, None
                ):
                    return self._finish_run(state_map, result)

            except AnsibleOptionsError as e:
                if not getattr(e, 'no_nexus_auth', False):
                    raise e

                state_map['failed']['default'] = {
                  'user': None, 'is_default': True,
                }

                if self._handle_modes(state_map, result):
                    display.vv('finish early deflogin opts error')
                    return self._finish_run(state_map, result)

        if not test_creds:
            display.vv('finish no test creds')
            return self._finish_run(state_map, result)

        ## also check optional explicit given test creds, if there are some:

        ## first ensure correct ordering of tested credentials
        prio_set = set()
        prio_map = {}

        for k,v in test_creds.items():
            p = v.get('priority', 0)
            prio_set.add(p)

            prio_map.setdefault(p, []).append((k,v))

        for p in sorted(prio_set):
            for x in prio_map[p]:
                k, v = x

                display.vv(
                   "NEXUS_CHECK_AUTH_CREDS :: test explicitly given test"\
                   " credential set '{}' (user={}) ...".format(k, v['user'])
                )

                if self._run_login_test(result, state_map, k, v['user'], v['password']):
                    return self._finish_run(state_map, result)

        return self._finish_run(state_map, result)

