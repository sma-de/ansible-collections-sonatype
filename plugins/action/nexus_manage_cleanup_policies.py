
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import collections
import copy
import datetime
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
          'policies': ([collections.abc.Mapping]),
          'policy_defaults': ([collections.abc.Mapping, type(None)], None),

          'state': (list(string_types), 'present', ['present', 'absent']),
          'exclusive': ([bool], False),
        })

        return tmp


    def _create_policy(self, cfg_pol, state_new, state_by_name):
        sid = cfg_pol['name']

        ## ## drop non-upstream keys not needed for this create-new usecase
        ## for x in ['force']:
        ##     cfg_repo.pop(x, None)

        res = self.create_nexus_cleanup_policy(cfg_pol)

        res['created_new'] = True
        res['change_state'] = 'created'
        state_new[sid] = res
        state_by_name[sid] = res


    def _get_diff_recv(self, cfg_cur, ex_cur, **kwargs):
        ignore_keys = {}

        if kwargs.get('toplvl', True):
            ##ignore_keys = {
            ##  'force': None,
            ##}

            kwargs.update(toplvl=False, cfg_top=cfg_cur, ex_top=ex_cur)

        is_map = True

        if isinstance(cfg_cur, list):
            itx = range(0, len(cfg_cur))
            is_map = False
        elif isinstance(cfg_cur, collections.abc.Mapping):
            ## assume map on default
            itx = cfg_cur.keys()
        else:
            return {
              'old': ex_cur, 'new': cfg_cur,
            }

        ##display.vvv(
        ##   "NEXUS_MANAGE_BLOBSTORES :: currently compare complex user"\
        ##   " config:\n{}\n\nwith existing server config:\n{}".format(
        ##       json.dumps(cfg_cur, indent=2),
        ##       json.dumps(ex_cur, indent=2),
        ##   )
        ##)

        cur_diff = {}

        for x in itx:
            if x in ignore_keys:
                continue

            v = cfg_cur[x]
            vo = ex_cur[x]

            if isinstance(v, list):
                v = sorted(v)

            if isinstance(vo, list):
                vo = sorted(vo)

            ##fn_cmp = getattr(self,
            ##  '_cmp_attr_typed_' + kwargs['store_type'], None
            ##)

            ##if fn_cmp:
            ##    if fn_cmp(x, v == vo, **kwargs):
            ##        # no diff here => noop
            ##        continue

            ##elif v == vo:
            if v == vo:
                # no diff here => noop
                continue

            k = x

            if not is_map:
                k = "[{}]".format(x)

            if isinstance(v, collections.abc.Mapping) \
              and isinstance(vo, collections.abc.Mapping):
                ## both are mapping, recurse down as mapping
                cur_diff_x = self._get_diff_recv(v, vo, **kwargs)
            elif isinstance(v, list) and isinstance(vo, list):
                ## both are lists, recurse down as lists
                cur_diff_x = self._get_diff_recv(v, vo, **kwargs)
            else:
                ## ## simple values or incompatible collection types,
                ## ## dont recurse
                ## if k in self.SECRET_KEYS:
                ##     ## hide secret values, assume that nexus already
                ##     ## obfuscate old values
                ##     v = '<< REDACTED >>'

                cur_diff_x = {'old': vo, 'new': v}

            if cur_diff_x:
                cur_diff[k] = cur_diff_x

        return cur_diff


    def _compare_policies(self, cfg_pol, ex_pol, state_updated):
        ##ex_pol = copy.deepcopy(ex_pol)
        ##cfg_pol = copy.deepcopy(cfg_pol)

        diff = self._get_diff_recv(cfg_pol, ex_pol)

        if diff:
            state_updated[cfg_pol['name']] = {'diff': diff}
            return True

        return False


    def _update_policy(self, cfg_pol, ex_pol,
        state_updated, state_by_name
    ):
        ## #### drop non-upstream keys not needed for this create-new usecase
        ## for x in ['force']:
        ##     cfg_repo.pop(x, None)

        ## ## note: repo updates are not allowed to be partial, so make
        ## ##   it always complete by taking every unchanged setting
        ## ##   from existing repo description
        ## tmp = copy.deepcopy(ex_repo)
        ## merge_dicts(tmp, cfg_repo)

        ## cfg_repo = tmp
        uid = cfg_pol['name']

        res = copy.deepcopy(cfg_pol)
        res.update(state_updated[uid])

        try:
            self.update_nexus_cleanup_policy(cfg_pol)

            ## read back current repo meta data and config
            res.update(self.read_nexus_cleanup_policy_config(
              cfg_pol
            ))

        except Exception as e:
            res['wanted_state'] = 'updated'
            state_updated.pop(uid)

            e.fail_details = res
            raise e

        res['updated'] = True
        res['change_state'] = 'updated'
        state_updated[uid] = res
        state_by_name[uid] = res


    def _delete_policy(self, ex_pol, state_removed, state_by_name):
        self.remove_nexus_cleanup_policy(ex_pol['name'])

        ex_pol['removed'] = True
        ex_pol['change_state'] = 'removed'
        state_removed[ex_pol['name']] = ex_pol
        state_by_name[ex_pol['name']] = ex_pol


    def run_specific(self, result):
        exclusive = self.get_taskparam('exclusive')

        ans_state_default = self.get_taskparam('state')
        cfg_pols = self.get_taskparam('policies')

        pol_defaults = self.get_taskparam('policy_defaults') or {}

        ## query all existing stores for given type
        display.vv(
           "NEXUS_MANAGE_CLEANUP_POLICIES :: query existing cleanup"\
           " policies from nexus ..."
        )

        existing_pols = self.get_nexus_cleanup_policies(
          return_as_map=True
        )

        display.vvv(
           "NEXUS_MANAGE_CLEANUP_POLICIES :: all cleanup policies currently"\
           " existing on nexus:\n{}".format(
              json.dumps(existing_pols, indent=2)
           )
        )

        state_by_name = {}
        state_new = {}
        state_updated = {}
        state_unchanged = {}
        state_removed = {}
        state_failed = {}

        absent_pols = {}

        ## loop through existing pols + cfg mapping parameter and
        ## determine per policy: create/update/nochange/delete
        for uk, uv in cfg_pols.items():
            display.vv(
               "NEXUS_MANAGE_CLEANUP_POLICIES :: handle config cleanup"\
               " policy '{}' ...".format(uk)
            )

            uv = merge_dicts(copy.deepcopy(pol_defaults), uv)

            setdefault_none(uv, 'ansible_state', ans_state_default)
            uv_ansstate = uv.pop('ansible_state')

            ex_pol = existing_pols.pop(uv['name'], None)

            try:
                if uv_ansstate == 'present':
                    if not ex_pol:
                        ## policy is new
                        display.vv(
                           "NEXUS_MANAGE_CLEANUP_POLICIES :: ... cleanup"\
                           " policy is new, create it"
                        )

                        self._create_policy(uv, state_new, state_by_name)
                        continue

                    if self._compare_policies(uv, ex_pol, state_updated):
                        ## config policy is somehow different to exisiting one
                        display.vv(
                           "NEXUS_MANAGE_CLEANUP_POLICIES :: ... cleanup"\
                           " policy exist but given config differs,"\
                           " update it"
                        )

                        self._update_policy(uv, ex_pol,
                          state_updated, state_by_name
                        )

                        continue

                    ex_pol['unchanged'] = True
                    ex_pol['change_state'] = 'unchanged'
                    state_unchanged[ex_pol['name']] = ex_pol
                    state_by_name[ex_pol['name']] = ex_pol
                    continue

                ## ans_state == absent, ensure user does not exist on nexus
                if ex_pol:
                    ex_pol['remove_reason'] = 'explicitly_absented'
                    absent_pols[uk] = ex_pol

            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = ex_pol or {'name': uv['name']}

                tmp['failed'] = True
                tmp['change_state'] = 'failed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed[tmp['name']] = tmp
                state_by_name[tmp['name']] = tmp

        if exclusive and existing_pols:
            ## in exclusive mode also kill all policies not
            ## explicitly mentionend by given config
            display.vv(
               "NEXUS_MANAGE_CLEANUP_POLICIES :: exclusive mode active,"\
               " remove also all existing cleanup policies not mentioned by"\
               " given config ..."
            )

            display.vvv(
               "NEXUS_MANAGE_CLEANUP_POLICIES :: existing cleanup"\
               " policies additionally removed because of exclusive"\
               " mode:\n{}".format(
                  json.dumps(existing_pols, indent=2)
               )
            )

            for k, v in existing_pols.items():
                state_unchanged.pop(v['name'], None)

                v['remove_reason'] = 'exclusive_mode'
                absent_pols[k] = v

        ## remove policies which should be removed
        for uk, uv in absent_pols.items():
            display.vv(
               "NEXUS_MANAGE_CLEANUP_POLICIES :: removing existing"\
               " cleanup policy '{}' ...".format(uk)
            )

            try:
                ## ## note: config repo stuff might still contains
                ## ##   settings important for delete operation like force
                ## cfg_rp = cfg_repos.get(uv['name'], None) or {}
                ## cfg_rp = merge_dicts(copy.deepcopy(repo_defaults), cfg_rp)

                self._delete_policy(uv, state_removed, state_by_name)

            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = uv

                tmp['failed'] = True
                tmp['change_state'] = 'failed'
                tmp['wanted_state'] = 'removed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed[tmp['name']] = tmp
                state_by_name[tmp['name']] = tmp

        ## export final state / changes of this call
        result['cleanup_policies'] = {
          'by_change': {
            'new': state_new,
            'updated': state_updated,
            'unchanged': state_unchanged,
            'removed': state_removed,
            'failed': state_failed,
          },

          'by_name': state_by_name,
        }

        if state_failed:
            result['failed'] = True
            result['msg'] = "Some kind of unexpected error happend"\
                            " while modifying these stores: {}".format(
                                list(state_failed.keys())
                            )

        elif state_new or state_updated or state_removed:
            result['changed'] = True

        return result

