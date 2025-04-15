
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
          'realm': (list(string_types), 'default'),
          'users': ([collections.abc.Mapping]),

          'user_defaults': ([collections.abc.Mapping, type(None)], None),

          'state': (list(string_types), 'present', ['present', 'absent']),
          'exclusive': ([bool], False),
        })

        return tmp


    def _prepare_usrcfg_for_print(self, cfg_usr):
        pw = cfg_usr.get('password', None)

        if pw:
            cfg_usr['password'] = '<redacted>'

        return json.dumps(cfg_usr, indent=2)


    def _handle_user_mailcfg(self, uid, cfg_usr, new_user=True):
        cfg_usr_fwd = copy.deepcopy(cfg_usr)

        mgen = cfg_usr_fwd.pop('mail', None) or {}
        em = cfg_usr.get('emailAddress', None)

        ## on default, auto mail gen is only applied for new
        ## users which dont have an explicit mail address defined,
        ## when this flag is active it also applied when determining
        ## needed updates for existing users, which means changing
        ## already existing mail addresses when they dont fit
        ## currently configured schema
        mgen_always = mgen.get('always', False)

        if em:
            if new_user or not mgen_always:
                ## an explicit mail address given, dont do mail auto-gen
                return cfg_usr_fwd

        if not mgen:
            raise AnsibleOptionsError(
               "Invalid cfg for new user '{}'. Cannot fill in"\
               " mandatory field 'emailAddress'. Either provide a"\
               " mail address explicitly or define mail auto-gen"\
               " settings with 'mail' submap:\n{}".format(
                  uid, self._prepare_usrcfg_for_print(cfg_usr)
               )
            )

        if not isinstance(mgen, collections.abc.Mapping):
            ## assume simple string containing domain
            mgen = {'domain': mgen}

        mdom = mgen.get('domain', None)

        if not mdom:
            raise AnsibleOptionsError(
               "Invalid cfg for new user '{}'. Cannot fill in"\
               " mandatory field 'emailAddress'. Found mail auto"\
               " generating submap config 'mail', but it misses"\
               " mandatory subkey 'domain':\n{}".format(
                  uid, self._prepare_usrcfg_for_print(cfg_usr)
               )
            )

        mail_fmt = setdefault_none(mgen,
           'format', "{user}-nxdef@{domain}"
        )

        usr_normer = mgen.get('norming', {}).get('user', {})

        user = uid

        for nk, nv in usr_normer.items():
            user = user.replace(nk, nv)

        cfg_usr['emailAddress'] = mail_fmt.format(user=user, domain=mdom)
        cfg_usr_fwd['emailAddress'] = cfg_usr['emailAddress']

        return cfg_usr_fwd


    def _create_user(self, cfg_usr, realm, state_new_users, state_by_name):
        uid = cfg_usr['id']

        if realm != 'default':
            pw = cfg_usr.get('password', None)

            if pw:
                cfg_usr['password'] = '<redacted>'

            raise AnsibleOptionsError(
                "Cannot handle user '{}' for realm '{}'. It seems not to"\
                " exist and creating new users is only allowed for nexus"\
                " builtin (default) realm:\n{}".format(
                    uid, realm, self._prepare_usrcfg_for_print(cfg_usr)
                )
            )

        ##
        ## note: it is absolutely mandatory to fill
        ##   out all user fields, apply sane
        ##   defaults where possible
        ##
        setdefault_none(cfg_usr, 'lastName', uid)
        setdefault_none(cfg_usr, 'firstName', uid)

        cfg_usr_up = self._handle_user_mailcfg(uid, cfg_usr)

        upw = cfg_usr.get('password', None)

        if not upw:
            raise AnsibleOptionsError(
               "Cannot create new user '{}', mandatory key 'password'"\
               " missing:\n{}".format(cfg_usr['id'],
                  self._prepare_usrcfg_for_print(cfg_usr)
               )
            )

        res = self.create_nexus_builtin_user(cfg_usr_up)

        ansible_assert(self.test_nexus_user_login(
             uid, upw, raise_error=False
           ),
           "post creation user test login failed for"\
           " user new '{}'".format(uid)
        )

        res['created_new'] = True
        cfg_usr['change_state'] = 'created'
        state_new_users[uid] = res
        state_by_name[uid] = res


    def _delete_user(self, cfg_usr, realm,
        state_removed_users, state_by_name
    ):
        fdel = cfg_usr.get('force_delete', False)

        if cfg_usr['id'] == self.nexus_auth_user:
            if not fdel:
                raise AnsibleOptionsError(
                   "Trying to remove nexus user '{}' which is also"\
                   " currently used for api access to the server, this"\
                   " seems dangerous. If you are really sure you want to"\
                   " do this set the optional 'force_delete' field true"\
                   "for this user:\n{}".format(cfg_usr['id'],
                      self._prepare_usrcfg_for_print(cfg_usr)
                   )
                )

        self.remove_nexus_user(cfg_usr['id'], realm)

        cfg_usr['removed'] = True
        cfg_usr['change_state'] = 'removed'
        state_removed_users[cfg_usr['id']] = cfg_usr
        state_by_name[cfg_usr['id']] = cfg_usr


    def _update_usr(self, cfg_usr, realm,
        state_updated_users, state_by_name
    ):
        cfg_usr = copy.deepcopy(cfg_usr)
        uid = cfg_usr['id']

        res = {}
        res.update(state_updated_users[uid])

        pw_change = res['diff'].get('password', None)
        pw_only = False

        res_with_usr = False

        try:
            if pw_change:
                pw_only = len(res['diff']) == 1
                npw = cfg_usr.pop('password', None)

                self.update_nexus_user_password(uid, npw, realm)

                ansible_assert(self.test_nexus_user_login(
                     uid, npw, raise_error=False
                   ),
                   "password change for user '{}' was requested and done but"\
                   " post change test login failed".format(uid)
                )

                res['changed_password'] = True

                ##
                ## if pw changed user is actually the one we currently use
                ## to auth rest calls against server, make sure to use
                ## new changed pw for future rest calls
                ##
                if uid == self.nexus_auth_user:
                    self._api_pw_override = npw

            res.update(copy.deepcopy(cfg_usr))
            res_with_usr = True

            if not pw_only:
                ## drop custom module update keys obviously not updateable by api
                for k in ['mail']:
                    cfg_usr.pop(k)

                self.update_nexus_user(cfg_usr, realm)

        except Exception as e:
            if not res_with_usr:
                res.update(copy.deepcopy(cfg_usr))

            res['planed_state'] = 'updated'
            state_updated_users.pop(uid)

            e.fail_details = res
            raise e

        res['updated'] = True
        res['change_state'] = 'updated'
        state_updated_users[uid] = res
        state_by_name[uid] = res


    def _compare_user(self, cfg_usr, ex_usr, state_updated_users):
        diff = {}
        ex_usr = copy.deepcopy(ex_usr)

        ## special pw key handling
        pw = cfg_usr.pop('password', None)

        if pw:
            ## do a test query to see if given combination of id + pw
            ## is already valid, if so, pw is not new and no diff,
            ## otherwise update is needed
            if not self.test_nexus_user_login(cfg_usr['id'], pw, raise_error=False):
                ## could not login with given password, it seems to
                ## be new and an update necessary
                diff['password'] = {
                   'old': '<unknown>', 'new': '<redacted>'
                }

                cfg_usr['password'] = pw

        ## special auto mail gen handling
        setdefault_none(cfg_usr, 'emailAddress', ex_usr['emailAddress'])
        self._handle_user_mailcfg(cfg_usr['id'], cfg_usr, new_user=False)

        for k, v in cfg_usr.items():
            if k == 'password':
                ## password not directly comparable and already handled
                continue

            if k in ['mail']:
                ## special module custom keys, not comparable
                continue

            curv = ex_usr.pop(k)

            if isinstance(v, list):
                v = sorted(v)
                curv = sorted(curv)

            if v != curv:
                diff[k] = {
                  'old': curv, 'new': v,
                }

        if diff:
            ##
            ## nexus rest api does not allow to update only a few new
            ## elements, you must always update the complete user
            ## object more or less
            ##
            cfg_usr.update(ex_usr)

            state_updated_users[cfg_usr['id']] = {'diff': diff}
            return True

        return False


    def run_specific(self, result):
        exclusive = self.get_taskparam('exclusive')

        realm = self.get_taskparam('realm')
        ans_state_default = self.get_taskparam('state')
        cfg_users = self.get_taskparam('users')

        usr_defaults = self.get_taskparam('user_defaults') or {}

        ## check if realm is valid
        self.check_user_source_valid(realm)

        ## query all existing users for given realm
        display.vv(
           "NEXUS_MANAGE_USER :: query existing users from nexus"\
           " for realm '{}' ...".format(realm)
        )

        existing_users = self.get_nexus_users(realm=realm)

        display.vvv(
           "NEXUS_MANAGE_USER :: all users currently existing on"\
           " nexus for realm:\n{}".format(
              json.dumps(existing_users, indent=2)
           )
        )

        state_by_name = {}
        state_new_users = {}
        state_updated_users = {}
        state_unchanged_users = {}
        state_removed_users = {}
        state_failed_users = {}

        absent_users = {}

        ## loop through existing users + user mapping parameter and determine per user: create/update/nochange/delete
        for uk, uv in cfg_users.items():
            display.vv(
               "NEXUS_MANAGE_USER :: handle config user '{}' ...".format(uk)
            )

            uv = merge_dicts(copy.deepcopy(usr_defaults), uv)

            setdefault_none(uv, 'ansible_state', ans_state_default)
            uv_ansstate = uv.pop('ansible_state')

            ex_usr = existing_users.pop(uv['id'], None)

            try:
                if uv_ansstate == 'present':
                    if not ex_usr:
                        ## user is new
                        display.vv(
                           "NEXUS_MANAGE_USER :: ... user is new, create it"
                        )

                        self._create_user(uv, realm,
                            state_new_users, state_by_name
                        )

                        continue

                    ## ## these keys are defined here by us for various
                    ## ## purposes and not part of upstream rest api and
                    ## ## only needed when creating new user accounts, can
                    ## ## and should be dropped at this point to avoid
                    ## ## issues with them in later user processing
                    ## custom_genkeys = []

                    ## for ck in custom_genkeys:
                    ##     uv.pop(ck, None)

                    if self._compare_user(uv, ex_usr, state_updated_users):
                        ## config user is somehow different to exisiting user
                        display.vv(
                           "NEXUS_MANAGE_USER :: ... user exist but given"\
                           " config differs, update them"
                        )

                        self._update_usr(uv, realm,
                            state_updated_users, state_by_name
                        )

                        continue

                    ex_usr['unchanged'] = True
                    ex_usr['change_state'] = 'unchanged'
                    state_unchanged_users[ex_usr['id']] = ex_usr
                    state_by_name[ex_usr['id']] = ex_usr
                    continue

                ## ans_state == absent, ensure user does not exist on nexus
                if ex_usr:
                    ex_usr['remove_reason'] = 'explicitly_absented'
                    absent_users[uk] = ex_usr

            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = ex_usr or {'id': uv['id']}

                tmp['failed'] = True
                tmp['change_state'] = 'failed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed_users[ex_usr['id']] = tmp
                state_by_name[ex_usr['id']] = tmp

        if exclusive and existing_users:
            ## in exclusive mode also kill all users not
            ## explicitly mentionend by given config
            display.vv(
               "NEXUS_MANAGE_USER :: exclusive mode active, remove also"\
               " all existing users not mentioned by given config ..."
            )

            display.vvv(
               "NEXUS_MANAGE_USER :: existing users additionally removed"\
               " because of exclusive mode:\n{}".format(
                  json.dumps(existing_users, indent=2)
               )
            )

            for k, v in existing_users.items():
                state_unchanged_users.pop(v['id'], None)

                v['remove_reason'] = 'exclusive_mode'
                absent_users[k] = v

        ## remove users which should be removed
        for uk, uv in absent_users.items():
            display.vv(
               "NEXUS_MANAGE_USER :: removing existing user '{}'".format(uk)
            )

            try:
                self._delete_user(uv, realm,
                    state_removed_users, state_by_name
                )
            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = uv

                tmp['failed'] = True
                tmp['change_state'] = 'failed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed_users[tmp['id']] = tmp
                state_by_name[tmp['id']] = tmp

        ## export final state / changes of this call
        auth_user = None
        auth_user_pw_change = False

        for k, v in state_by_name.items():
            if v['id'] == self.nexus_auth_user:
                v['current_auth_user'] = True
                auth_user = v

                if v.get('changed_password', False):
                    auth_user_pw_change = True

        result['users'] = {
          'by_change': {
            'new': state_new_users,
            'updated': state_updated_users,
            'unchanged': state_unchanged_users,
            'removed': state_removed_users,
            'failed': state_failed_users,
          },

          'by_name': state_by_name,
        }

        if auth_user:
            result['users']['current_auth_user'] = auth_user
            result['users']['auth_user_pw_change'] = auth_user_pw_change

        if state_failed_users:
            result['failed'] = True
            result['msg'] = "Some kind of unexpected error happend"\
                            " while modifying these users: {}".format(
                                list(state_failed_users.keys())
                            )

        elif state_new_users or state_updated_users or state_removed_users:
            result['changed'] = True

        return result

