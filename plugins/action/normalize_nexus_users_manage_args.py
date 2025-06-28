
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import copy

from ansible.errors import AnsibleOptionsError
from ansible.plugins.filter.core import to_bool
from ansible.utils.display import Display

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import\
  ConfigNormalizerBaseMerger,\
  NormalizerBase,\
  NormalizerNamed,\
  DefaultSetterConstant,\
  SIMPLEKEY_IGNORE_VAL

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.web_service import\
  SecureConnectionNormer

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import get_subdict, setdefault_none, SUBDICT_METAKEY_ANY

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert

display = Display()


class NexusUserManageNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (ConnectionNormer, True),
          NormUsers(pluginref),
        ]

        super(NexusUserManageNormalizer, self).__init__(pluginref, *args, **kwargs)


class ConnectionNormer(SecureConnectionNormer):

    NORMER_CONFIG_PATH = ['connection']

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(pluginref, *args,
            srvtype_default='sonanexus',
            config_path=self.NORMER_CONFIG_PATH, **kwargs
        )


class NormUsers(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormUserRealmInst(pluginref),
          AnonymousAccessNormer(pluginref),
        ]

        super(NormUsers, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['users']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        exp_configs = {}
        my_subcfg['_export_cfgs'] = exp_configs

        ## prepare use cred handling subconfig and optional
        ## user role generation
        user_creds = {}
        exp_configs['user_creds'] = user_creds

        user_roles = {}

        tmp = {}

        for kr, vr in my_subcfg['realms'].items():
            realm_roles = {}

            for ku, vu in vr['users'].items():
                ## handle creds stuff
                pw_opts = vu.get('credentials', {}).get('password', {})

                if pw_opts.get('enabled', False):
                    pw_opts = copy.deepcopy(pw_opts)

                    pthrough = [
                      'auto_create', 'stores', 'enable_default_stores',
                    ]

                    for x in pthrough:
                        if x not in pw_opts:
                            continue

                        sm = setdefault_none(pw_opts, 'credential', {})
                        sm[x] = pw_opts.pop(x)

                    tmp[vu['id']] = pw_opts

                ## handle roles stuff
                rdef = vu.get('role_def', None)

                if rdef:
                    realm_roles[rdef['id']] = rdef

            if realm_roles:
                user_roles[kr] = {'roles': realm_roles}

        if tmp:
            user_creds['passwords'] = {
              'pw_defaults': {'reversable': True},
              'passwords': tmp,
            }

        if user_roles:
            exp_configs['user_roles'] = {
              'roles': {'sources': user_roles}
            }

        return my_subcfg



class AnonymousAccessNormer(NormalizerBase):

##    def __init__(self, pluginref, *args, **kwargs):
##        super(AnonymousAccessNormer, self).__init__(pluginref, *args, **kwargs)


    @property
    def simpleform_key(self):
        return '_sm_form_val'

    @property
    def config_path(self):
        return ['anonymous_access']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        def_ena = False
        smf_val= my_subcfg.pop('_sm_form_val', None)

        if my_subcfg or smf_val is not None:
            if len(my_subcfg) > 1 or 'enabled' not in my_subcfg:
                def_ena = True
            elif smf_val is not None:
                def_ena = True

        setdefault_none(my_subcfg, 'enabled', def_ena)
        c = setdefault_none(my_subcfg, 'config', {})

        if my_subcfg['enabled']:
            setdefault_none(c, 'state', 'present')

            if smf_val is not None and not smf_val:
                c['state'] = 'absent'

        return my_subcfg



class NormUserRealmInst(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'exclusive', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormRealmUserDefaults(pluginref),
          NormRealmUserInst(pluginref),
        ]

        super(NormUserRealmInst, self).__init__(pluginref, *args, **kwargs)


    @property
    def name_key(self):
        return 'id'

    @property
    def config_path(self):
        return ['realms', SUBDICT_METAKEY_ANY]


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        ## package configuration into format fitting for used modules
        cfg_man_users = {
          'realm': my_subcfg['id'],
          'exclusive': my_subcfg['exclusive'],
          'state': my_subcfg['user_defaults']['state'],

          'users': {},

          'user_defaults': my_subcfg['user_defaults']['config'],
        }

        for uk, uv in my_subcfg.get('users', {}).items():
            cfg_man_users['users'][uk] = uv['config']

        my_subcfg['_export_cfgs'] = {
          'manage_users': cfg_man_users,
        }

        return my_subcfg


class NormRealmUserDefaults(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'state', DefaultSetterConstant('present')
        )

        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        super(NormRealmUserDefaults, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['user_defaults']


class NormRealmUserInst(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormUserRoleX(pluginref),
          (NormUserCreds, True),
          NormUserConfig(pluginref),
        ]

        super(NormRealmUserInst, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['users', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'id'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        rdef = my_subcfg.get('role_def', None)

        if rdef:
            ## default role-id from user id
            rid = setdefault_none(rdef, 'id', my_subcfg['id'].replace('_', '-'))

            ## auto-add user special role to roles of user
            roles = setdefault_none(my_subcfg, 'roles', {})
            roles[rid] = None

        return my_subcfg


class NormUserRoleX(NormalizerNamed):

    @property
    def config_path(self):
        return ['roles', SUBDICT_METAKEY_ANY]


class NormUserConfig(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'status', DefaultSetterConstant('active')
        )

        super(NormUserConfig, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['config']


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        my_subcfg['id'] = pcfg['id']

        roles = []
        for k, v in pcfg['roles'].items():
            roles.append(v['name'])

        my_subcfg['roles'] = roles
        return my_subcfg



class NormUserCreds(NormalizerBase):

    NORMER_CONFIG_PATH = ['credentials']

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (NormUserCredPw, True),
        ]

        super(NormUserCreds, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH



class NormUserCredPw(NormalizerBase):

    NORMER_CONFIG_PATH = ['password']


    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'enabled', DefaultSetterConstant(True)
        )

        super(NormUserCredPw, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    @property
    def simpleform_key(self):
        return 'value'



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           NexusUserManageNormalizer(self), *args,
           default_merge_vars=[
             'smabot_sonatype_manage_nexus_users_args_defaults',
             'smabot_sonatype_manage_nexus_users_args_extra_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_sonatype_manage_nexus_users_args'

