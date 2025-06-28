
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

    ROLES_UNCHANGEABLE_ATTRIBUTES = ['source', 'readOnly']

    UNCHANGEABLE_DEFAULT_INTERNAL_ROLES = {
      'nx-admin': None,
      'nx-anonymous': None,
    }


    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        tmp.update({
          'role_defaults': ([collections.abc.Mapping, type(None)], None),
          'role_ignores': ([collections.abc.Mapping, type(None)], None),

          'roles': ([collections.abc.Mapping]),

          ##
          ## in theory this could be used for external role mappings
          ## (other sources) like it is already possible in the webui,
          ## in practice this seems currently unsupported by sonatype:
          ##
          ##  -> https://community.sonatype.com/t/how-to-create-an-external-ldap-role-using-the-rest-api/8842/2
          ##
          ## others say it might work simply ba magic name mapping (??):
          ##
          ##  -> https://community.sonatype.com/t/is-it-possible-to-create-a-saml-external-role-using-the-rest-api/9132/3
          ##
          'source': (list(string_types), 'default', ['default']),

          'state': (list(string_types), 'present', ['present', 'absent']),
          'exclusive': ([bool], False),
        })

        return tmp


    def _create_role(self, cfg_role, source, state_new_roles, state_by_name):
        rid = cfg_role['id']

        res = self.create_nexus_role(cfg_role, source=source)

        res['created_new'] = True
        cfg_role['change_state'] = 'created'
        state_new_roles[rid] = res
        state_by_name[rid] = res


    def _delete_role(self, cfg_role, source,
        state_removed_roles, state_by_name
    ):
        self.remove_nexus_role(cfg_role['id'], source=source)

        cfg_role['removed'] = True
        cfg_role['change_state'] = 'removed'
        state_removed_roles[cfg_role['id']] = cfg_role
        state_by_name[cfg_role['id']] = cfg_role


    def _update_role(self, cfg_role, source,
        state_updated_roles, state_by_name
    ):
        cfg_role_cpy = copy.deepcopy(cfg_role)
        rid = cfg_role['id']

        res = copy.deepcopy(cfg_role)
        res.update(state_updated_roles[rid])

        ## remove builtin pseudo attributes we cannot change
        for x in self.ROLES_UNCHANGEABLE_ATTRIBUTES:
            cfg_role_cpy.pop(x)

        try:
            self.update_nexus_role(cfg_role_cpy, source=source)

        except Exception as e:
            res['planed_state'] = 'updated'
            state_updated_roles.pop(rid)

            e.fail_details = res
            raise e

        res['updated'] = True
        res['change_state'] = 'updated'
        state_updated_roles[rid] = res
        state_by_name[rid] = res


    def _compare_role(self, cgf_role, ex_role, state_updated_roles):
        diff = {}
        ex_role = copy.deepcopy(ex_role)

        for k, v in cgf_role.items():
            curv = ex_role.pop(k)

            if isinstance(v, list):
                v = sorted(v)
                curv = sorted(curv)

            if v != curv:
                if k in self.ROLES_UNCHANGEABLE_ATTRIBUTES:
                    raise AnsibleOptionsError(
                       "Invalid cfg for role '{}'. Found value diff"\
                       " for unchangeable attribute '{}':"\
                       " \n  '{}' != '{}'".format(cfg_role['id'], k,
                          v, curv
                       )
                    )

                diff[k] = {
                  'old': curv, 'new': v,
                }

        if diff:
            ##
            ## nexus rest api does not allow to update only a few new
            ## elements, you must always update the complete user
            ## object more or less
            ##
            cgf_role.update(ex_role)

            state_updated_roles[cgf_role['id']] = {'diff': diff}
            return True

        return False


    def create_deps_safe_role_ordering(self, cfg_roles, existing_roles,
        cur_role=None, ordering=None, handled_deps=None, exclusive=None,
        role_ignores=None, ans_state_default=None, parent_chain=None
    ):
        if ordering is None:
            # init algo and end it too
            ordering = []
            parent_chain = []
            handled_deps = {}

            for k, v in cfg_roles.items():
                setdefault_none(v, 'id', k)

                self.create_deps_safe_role_ordering(cfg_roles,
                    existing_roles, cur_role=v, ordering=ordering,
                    handled_deps=handled_deps, exclusive=exclusive,
                    role_ignores=role_ignores,
                    ans_state_default=ans_state_default,
                    parent_chain=parent_chain
                )

            return ordering

        cid = cur_role['id']
        setdefault_none(cur_role, 'ansible_state', ans_state_default)

        errmsg = "Bad role configuration given, role '{}'".format(cid)

        if parent_chain:
            errmsg += " first found as dependency of '{}'".format(
                '.'.join(parent_chain)
            )

        if cid in parent_chain:
            raise AnsibleOptionsError(
                "{} is circular dependend on itself".format(errmsg)
            )

        if cid in handled_deps:
            ## we did this role (and its dependencies already, noop here
            return

        ex_role = existing_roles.get(cid, {})
        sub_roles = cur_role.get('roles', None)

        if sub_roles is None:
            ## if given role configuration contains a role list, use that,
            ## but as this description is allowed to be incomplete
            ## fallback to already defined role deps in nexus server for
            ## this role if it exists already
            sub_roles = ex_role.get('roles', None)

        if not sub_roles:
            ## current role does not depend on any other role,
            ## we are done here
            if cid in cfg_roles:
                ordering.append(cid)
                handled_deps[cid] = True

            return ordering

        for srk in sub_roles:
            ## map role id to real role, check if it is valid
            srv = cfg_roles.get(srk, None)

            errmsg_sr = "{} has a sub-role with id '{}' as"\
                        " dependency defined,".format(errmsg, srk)

            if srv:
                setdefault_none(srv, 'id', srk)
                setdefault_none(srv, 'ansible_state', ans_state_default)

                if cur_role['ansible_state'] != 'absent':
                    if srv['ansible_state'] == 'absent':
                        raise AnsibleOptionsError(
                            "{} but this sub-role is configured"\
                            " to be removed:\n{}".format(errmsg_sr,
                                json.dumps(srv, indent=2)
                            )
                        )

            else:
                ex_srv = existing_roles.get(srk, None)

                if not ex_srv:
                    raise AnsibleOptionsError(
                        "{} but this sub-role is neither part of given role"\
                        " configuration set nor does it already exist on"\
                        " server".format(errmsg_sr)
                    )

                if exclusive:
                    if ex_srv['id'] not in role_ignores \
                       and ex_srv['id'] not in self.UNCHANGEABLE_DEFAULT_INTERNAL_ROLES:
                            raise AnsibleOptionsError(
                                "{} but this sub-role is scheduled to be"\
                                " removed based on the exclusive_mode"\
                                " criteria".format(errmsg_sr)
                            )

                srv = ex_srv

            ## recursve down for sub-role
            parent_chain.append(cur_role['id'])

            self.create_deps_safe_role_ordering(cfg_roles,
                existing_roles, cur_role=srv, ordering=ordering,
                handled_deps=handled_deps, exclusive=exclusive,
                role_ignores=role_ignores,
                ans_state_default=ans_state_default,
                parent_chain=parent_chain
            )

            parent_chain.pop()

        ## all my sub dep roles handled, now it should be safe
        ## to handle this role
        if cid in cfg_roles:
            ordering.append(cid)
            handled_deps[cid] = True

        return ordering


    def run_specific(self, result):
        exclusive = self.get_taskparam('exclusive')

        source = self.get_taskparam('source')

        ans_state_default = self.get_taskparam('state')
        cfg_roles = self.get_taskparam('roles')

        role_defaults = self.get_taskparam('role_defaults') or {}
        role_ignores = self.get_taskparam('role_ignores') or {}

        # TODO: can we check validity of source here somehow??

        ## query all existing server roles
        display.vv(
           "NEXUS_MANAGE_ROLES :: query existing roles from nexus"\
           " for source '{}' ...".format(source)
        )

        existing_roles = self.get_nexus_roles(source=source)

        display.vvv(
           "NEXUS_MANAGE_ROLES :: all roles currently existing on"\
           " nexus for current source:\n{}".format(
              json.dumps(existing_roles, indent=2)
           )
        )

        state_by_name = {}
        state_new_roles = {}
        state_updated_roles = {}
        state_unchanged_roles = {}
        state_removed_roles = {}
        state_failed_roles = {}

        absent_roles = {}
        absent_roles_order = []

        ## loop through existing users + user mapping parameter and
        ## determine per user: create/update/nochange/delete
        order = self.create_deps_safe_role_ordering(cfg_roles,
            existing_roles, exclusive=exclusive, role_ignores=role_ignores,
            ans_state_default=ans_state_default
        )

        for rk in order:
            rv = cfg_roles[rk]

            display.vv(
               "NEXUS_MANAGE_ROLES :: handle config role '{}' ...".format(rk)
            )

            rv = merge_dicts(copy.deepcopy(role_defaults), rv)

            setdefault_none(rv, 'name', rv['id'])

            ##
            ## empty description is allowed, but interestingly when
            ## creating roles per rest-api not gicing any description
            ## let's nexus default it to role-name or role-id,
            ## which is not the behaviour of webui
            ##
            setdefault_none(rv, 'description', '')

            rv_ansstate = rv.pop('ansible_state')

            ex_role = existing_roles.pop(rv['id'], None)

            try:
                if rv_ansstate == 'present':
                    if not ex_role:
                        ## user is new
                        display.vv(
                           "NEXUS_MANAGE_ROLES :: ... role is new, create it"
                        )

                        self._create_role(rv, source,
                            state_new_roles, state_by_name
                        )

                        continue

                    if self._compare_role(rv, ex_role, state_updated_roles):
                        ## config user is somehow different to exisiting role
                        display.vv(
                           "NEXUS_MANAGE_ROLES :: ... role exist but given"\
                           " config differs, update it"
                        )

                        self._update_role(rv, source,
                            state_updated_roles, state_by_name
                        )

                        continue

                    ex_role['unchanged'] = True
                    ex_role['change_state'] = 'unchanged'
                    state_unchanged_roles[ex_role['id']] = ex_role
                    state_by_name[ex_role['id']] = ex_role
                    continue

                ## ans_state == absent, ensure user does not exist on nexus
                if ex_role:
                    ex_role['remove_reason'] = 'explicitly_absented'
                    absent_roles[rk] = ex_role
                    absent_roles_order.append(rk)

            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = ex_role or {'id': rv['id']}

                tmp['failed'] = True
                tmp['change_state'] = 'failed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed_roles[ex_role['id']] = tmp
                state_by_name[ex_role['id']] = tmp

        if exclusive and existing_roles:
            ## in exclusive mode also kill all roles not
            ## explicitly mentionend by given config
            display.vv(
               "NEXUS_MANAGE_ROLES :: exclusive mode active, remove also"\
               " all existing roles not mentioned by given config ..."
            )

            roles_killed = {}
            roles_kept = {}

            for k, v in existing_roles.items():
                if v['id'] in role_ignores \
                   or v['id'] in self.UNCHANGEABLE_DEFAULT_INTERNAL_ROLES:

                    ## skip roles ignored from forceful deletion
                    ## because of excliveness
                    roles_kept[k] = v
                    continue

                state_unchanged_roles.pop(v['id'], None)

                v['remove_reason'] = 'exclusive_mode'
                absent_roles[k] = v

                ## TODO: we might also have to proper order here if killed roles depen on each other???
                absent_roles_order.append(k)
                roles_killed[k] = v

            display.vvv(
               "NEXUS_MANAGE_ROLES :: existing roles additionally removed"\
               " because of exclusive mode:\n{}".format(
                  json.dumps(roles_killed, indent=2)
               )
            )

            display.vvv(
               "NEXUS_MANAGE_ROLES :: existing roles not managed by this"\
               " call and still kept around despite exclusive mode because"\
               "of role_ignores or they are unchangeable builtin default"\
               " roles:\n{}".format(json.dumps(roles_kept, indent=2))
            )

        ## remove users which should be removed
        for rk in absent_roles_order:
            rv = absent_roles[rk]

            display.vv(
               "NEXUS_MANAGE_ROLES :: removing existing role '{}'".format(rk)
            )

            try:
                self._delete_role(rv, source,
                    state_removed_roles, state_by_name
                )

            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = rv

                tmp['failed'] = True
                tmp['change_state'] = 'failed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed_roles[tmp['id']] = tmp
                state_by_name[tmp['id']] = tmp

        ## export final state / changes of this call
        result['roles'] = {
          'by_change': {
            'new': state_new_roles,
            'updated': state_updated_roles,
            'unchanged': state_unchanged_roles,
            'removed': state_removed_roles,
            'failed': state_failed_roles,
          },

          'by_name': state_by_name,
        }

        if state_failed_roles:
            result['failed'] = True
            result['msg'] = "Some kind of unexpected error happend"\
                            " while modifying these roles: {}".format(
                                list(state_failed_roles.keys())
                            )

        elif state_new_roles or state_updated_roles or state_removed_roles:
            result['changed'] = True

        return result

