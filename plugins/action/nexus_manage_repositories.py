
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
          'repo_format': (list(string_types), 'docker', ['docker']),
          'repo_type': (list(string_types), 'hosted', ['proxy', 'group', 'hosted']),

          'repositories': ([collections.abc.Mapping]),
          'repo_defaults': ([collections.abc.Mapping, type(None)], None),

          'exclusion_ignores': ([collections.abc.Mapping, type(None)], None),

          'state': (list(string_types), 'present', ['present', 'absent']),
          'exclusive': ([bool, type(None)] + list(string_types), False,
             [True, False, None, 'all', 'type', 'format']
          ),

          'no_default_repos': ([bool], False),

          'adapt_auth_realms': ([bool], True),
        })

        return tmp


    def _create_repo(self, cfg_repo, repo_format, repo_type,
        state_new, state_by_name
    ):
        sid = cfg_repo['name']

        ## drop non-upstream keys not needed for this create-new usecase
        for x in ['force']:
            cfg_repo.pop(x, None)

        self.create_nexus_repository(repo_format, repo_type, cfg_repo)

        ## read back current repo meta data and config
        res = self.read_nexus_repo_config(repo_format, repo_type, cfg_repo)
        res.update(self.get_nexus_repo_details(cfg_repo))

        res['created_new'] = True
        res['change_state'] = 'created'
        state_new[sid] = res
        state_by_name[sid] = res


    def _get_diff_recv(self, cfg_cur, ex_cur, **kwargs):
        ignore_keys = {}

        if kwargs.get('toplvl', True):
            ignore_keys = {
              'force': None,
            }

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

                cur_diff_x = {'old': v, 'new': vo}

            if cur_diff_x:
                cur_diff[k] = cur_diff_x

        return cur_diff


    def _compare_repos(self, cfg_repo, ex_repo, state_updated):
        ##ex_repo = copy.deepcopy(ex_repo)
        ##cfg_repo = copy.deepcopy(cfg_repo)

        diff = self._get_diff_recv(cfg_repo, ex_repo)

        if diff:
            state_updated[cfg_repo['name']] = {'diff': diff}
            return True

        return False


    def _update_repo(self, cfg_repo, ex_repo, repo_format, repo_type,
        state_updated, state_by_name
    ):
        #### drop non-upstream keys not needed for this create-new usecase
        for x in ['force']:
            cfg_repo.pop(x, None)

        ## note: repo updates are not allowed to be partial, so make
        ##   it always complete by taking every unchanged setting
        ##   from existing repo description
        tmp = copy.deepcopy(ex_repo)
        merge_dicts(tmp, cfg_repo)

        cfg_repo = tmp
        uid = cfg_repo['name']

        res = copy.deepcopy(cfg_repo)
        res.update(state_updated[uid])

        try:
            self.update_nexus_repository(
              repo_format, repo_type, cfg_repo
            )

            ## read back current repo meta data and config
            res.update(self.read_nexus_repo_config(
              repo_format, repo_type, cfg_repo
            ))

            res.update(self.get_nexus_repo_details(cfg_repo))

        except Exception as e:
            res['wanted_state'] = 'updated'
            state_updated.pop(uid)

            e.fail_details = res
            raise e

        res['updated'] = True
        res['change_state'] = 'updated'
        state_updated[uid] = res
        state_by_name[uid] = res


    def _delete_repo(self, ex_repo, cfg_repo, repo_type,
      state_removed, state_by_name
    ):
        repd = self.get_nexus_repo_details(ex_repo)

        if repo_type == 'hosted' and repd.get('size', 0) > 0:
            ## removed non-empty hosted repos only when special force
            ## flag is set to guard against data loss
            ansible_assert(cfg_repo.pop('force', False),
              "trying to remove non-empty hosted repository '{}', if this"\
              " is really acceptable set force flag to true:\n{}".format(
                  ex_repo['name'], ex_repo
              )
            )

        self.remove_nexus_repository(ex_repo['name'])

        ex_repo['removed'] = True
        ex_repo['change_state'] = 'removed'
        state_removed[ex_repo['name']] = ex_repo
        state_by_name[ex_repo['name']] = ex_repo


    def run_specific(self, result):
        exclusive = self.get_taskparam('exclusive')

        rp_form = self.get_taskparam('repo_format')
        rp_type = self.get_taskparam('repo_type')
        ans_state_default = self.get_taskparam('state')
        cfg_repos = self.get_taskparam('repositories')

        no_def_repos = self.get_taskparam('no_default_repos')
        repo_defaults = self.get_taskparam('repo_defaults') or {}

        exclude_ignore = self.get_taskparam('exclusion_ignores') or {}

        adapt_auth_realms = self.get_taskparam('adapt_auth_realms')

        ## query all existing stores for given type
        display.vv(
           "NEXUS_MANAGE_REPOSITORIES :: query existing repositories"\
           " from nexus ..."
        )

        existing_repos = self.get_nexus_repositories(
          details=True, return_as_map=True
        )

        display.vvv(
           "NEXUS_MANAGE_REPOSITORIES :: all repositories currently existing on"\
           " nexus:\n{}".format(json.dumps(existing_repos, indent=2))
        )

        state_by_name = {}
        state_new = {}
        state_updated = {}
        state_unchanged = {}
        state_removed = {}
        state_failed = {}

        absent_repos = {}

        ## loop through existing repos + cfg mapping parameter and
        ## determine per repos: create/update/nochange/delete
        for uk, uv in cfg_repos.items():
            display.vv(
               "NEXUS_MANAGE_REPOSITORIES :: handle config repository"\
               " '{}' ...".format(uk)
            )

            uv = merge_dicts(copy.deepcopy(repo_defaults), uv)

            setdefault_none(uv, 'ansible_state', ans_state_default)
            uv_ansstate = uv.pop('ansible_state')

            ex_repo = existing_repos.pop(uv['name'], None)

            try:
                if uv_ansstate == 'present':
                    bsname = uv.get('storage', {}).get(
                      'blobStoreName', None
                    ) or 'default'

                    ansible_assert(
                      bsname != 'default' or not no_def_repos,
                        "bad config repo '{}', either blobstore is"\
                        " explicitly set to 'default' or it will be auto"\
                        " defaulted to 'default' blobstore while at the"\
                        " same time 'no_default_repos' flag is set true:"\
                        "\n{}".format(uv['name'], uv)
                    )

                    if not ex_repo:
                        ## store is new
                        display.vv(
                           "NEXUS_MANAGE_REPOSITORIES :: ... repo"\
                           " is new, create it"
                        )

                        self._create_repo(uv, rp_form, rp_type,
                          state_new, state_by_name,
                        )

                        continue

                    ansible_assert(
                      ex_repo['format'] == rp_form,
                        "cannot convert between different repository"\
                        " formats, given config value '{}' does not match"\
                        " real value '{}' for already existing"\
                        " repo '{}'".format(rp_form, ex_repo['format'],
                           ex_repo['name'],
                        )
                    )

                    ansible_assert(
                      ex_repo['type'] == rp_type,
                        "cannot convert between different repository"\
                        " types, given config value '{}' does not match"\
                        " real value '{}' for already existing"\
                        " repo '{}'".format(rp_type, ex_repo['type'],
                           ex_repo['name'],
                        )
                    )

                    if self._compare_repos(uv, ex_repo, state_updated):
                        ## config store is somehow different to exisiting store
                        display.vv(
                           "NEXUS_MANAGE_REPOSITORIES :: ... repo exist but"\
                           " given config differs, update them"
                        )

                        self._update_repo(uv, ex_repo, rp_form, rp_type,
                           state_updated, state_by_name
                        )

                        continue

                    ex_repo['unchanged'] = True
                    ex_repo['change_state'] = 'unchanged'
                    state_unchanged[ex_repo['name']] = ex_repo
                    state_by_name[ex_repo['name']] = ex_repo
                    continue

                ## ans_state == absent, ensure user does not exist on nexus
                if ex_repo:
                    ex_repo['remove_reason'] = 'explicitly_absented'
                    absent_repos[uk] = ex_repo

            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = ex_repo or {'name': uv['name']}

                tmp['failed'] = True
                tmp['change_state'] = 'failed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed[tmp['name']] = tmp
                state_by_name[tmp['name']] = tmp

        if no_def_repos and existing_repos:
            display.vv(
               "NEXUS_MANAGE_REPOSITORIES :: no_default_repos mode active,"\
               " remove also all existing repositories where blobstore"\
               " is 'default' ..."
            )

            def_repos = {}

            for k in list(existing_repos.keys()):
                v = existing_repos[k]

                if v['storage']['blobStoreName'] == 'default':
                    existing_repos.pop(k)
                    def_repos[k] = v

            display.vvv(
               "NEXUS_MANAGE_REPOSITORIES :: existing stores additionally"\
               " removed because of no_default_repos setting:\n{}".format(
                  json.dumps(def_repos, indent=2)
               )
            )

            for k, v in def_repos.items():
                state_unchanged.pop(v['name'], None)

                v['remove_reason'] = 'no_default_repos'
                absent_repos[k] = v

        if exclusive == True:
            ## if exclusive is given as simple bool, assume the most
            ## restricted exlusiveness (format+type)
            exclusive = 'type'

        if exclusive and existing_repos:
            ## in exclusive mode also kill all stores not
            ## explicitly mentionend by given config
            display.vv(
               "NEXUS_MANAGE_REPOSITORIES :: exclusive mode ({}) active,"\
               " remove also all existing repositories not mentioned by"\
               " given config ...".format(exclusive)
            )

            if exclusive != 'all':
                ## restrictive exclusiveness, filter out some repos
                for k in list(existing_repos.keys()):
                    v = existing_repos[k]

                    if exclusive == 'format' or exclusive == 'type':
                        ## filter out repos with mismatching format
                        if v['format'].lower() != rp_form.lower():
                            existing_repos.pop(k)
                            continue

                    if exclusive == 'type':
                        ## filter out repos with mismatching type
                        if v['type'].lower() != rp_type.lower():
                            existing_repos.pop(k)

            for k in list(existing_repos.keys()):
                if exclude_ignore.get(k, False):
                    ## filter out repos explicitly "saved"
                    ## by exclusion_ignores mapping
                    existing_repos.pop(k)

            display.vvv(
               "NEXUS_MANAGE_REPOSITORIES :: existing stores additionally"\
               " removed because of exclusive mode:\n{}".format(
                  json.dumps(existing_repos, indent=2)
               )
            )

            for k, v in existing_repos.items():
                state_unchanged.pop(v['name'], None)

                v['remove_reason'] = 'exclusive_mode'
                absent_repos[k] = v

        ## remove users which should be removed
        for uk, uv in absent_repos.items():
            display.vv(
               "NEXUS_MANAGE_REPOSITORIES :: removing existing"\
               " repo '{}' ...".format(uk)
            )

            try:
                ## note: config repo stuff might still contains
                ##   settings important for delete operation like force
                cfg_rp = cfg_repos.get(uv['name'], None) or {}
                cfg_rp = merge_dicts(copy.deepcopy(repo_defaults), cfg_rp)

                self._delete_repo(uv, cfg_rp, rp_type,
                  state_removed, state_by_name
                )

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

        ## do special case handlings
        if rp_form == 'docker':
            if adapt_auth_realms:
                if state_new or state_updated or state_unchanged:
                    ## if we currently do docker hosted repos have at
                    ## least one living such repo and auth realm handling
                    ## is not explicitly disabled, ensure docker bearer
                    ## realm is active
                    display.vv(
                       "NEXUS_MANAGE_REPOSITORIES :: ensuring docker"\
                       " bearer auth realm is active ..."
                    )

                    res = self.ensure_realms_are_active("DockerToken")

                    if res:
                        _, realm_diff = res
                        result['active_realm_changes'] = realm_diff
                        result['changed'] = True

                elif exclusive in ['all', 'format']:
                    ## if we currently do docker hosted repos have no
                    ## living repos and in exclusive mode and auth realm
                    ## handling is not explicitly disabled, ensure docker
                    ## bearer realm is not active
                    display.vv(
                       "NEXUS_MANAGE_REPOSITORIES :: ensuring docker"\
                       " bearer auth realm is deactivated because of"\
                       " exclusive settings ..."
                    )

                    res = self.ensure_realms_are_deactive("DockerToken")

                    if res:
                        _, realm_diff = res
                        result['active_realm_changes'] = realm_diff
                        result['changed'] = True

        ## export final state / changes of this call
        result['repos'] = {
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

