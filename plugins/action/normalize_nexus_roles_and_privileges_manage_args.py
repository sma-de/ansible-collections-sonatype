
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


class NexusRolesPrivManageRootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (ConnectionNormer, True),
          NormRoles(pluginref),
        ]

        super(NexusRolesPrivManageRootNormer, self).__init__(pluginref, *args, **kwargs)


class ConnectionNormer(SecureConnectionNormer):

    NORMER_CONFIG_PATH = ['connection']

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(pluginref, *args,
            srvtype_default='sonanexus',
            config_path=self.NORMER_CONFIG_PATH, **kwargs
        )


class NormRoles(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormRoleSourceInst(pluginref),
        ]

        super(NormRoles, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['roles']


class NormRoleSourceInst(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'exclusive', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormRoleDefaults(pluginref),
          NormSourcedRoleInst(pluginref),
        ]

        super(NormRoleSourceInst, self).__init__(pluginref, *args, **kwargs)


    @property
    def name_key(self):
        return 'id'

    @property
    def config_path(self):
        return ['sources', SUBDICT_METAKEY_ANY]


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        ## package configuration into format fitting for used modules
        cfg_man_roles = {
          'source': my_subcfg['id'],
          'exclusive': my_subcfg['exclusive'],
          'state': my_subcfg['role_defaults']['state'],
          'role_defaults': my_subcfg['role_defaults']['config'],

          'roles': {},
        }

        for rk, rv in my_subcfg.get('roles', {}).items():
            cfg_man_roles['roles'][rk] = rv

        tmp = my_subcfg.get('role_ignores', None)

        if tmp:
            cfg_man_roles['role_ignores'] = tmp

        my_subcfg['_export_cfgs'] = {
          'manage_roles': cfg_man_roles,
        }

        return my_subcfg


class NormRoleDefaults(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'state', DefaultSetterConstant('present')
        )

        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        super(NormRoleDefaults, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['role_defaults']


class NormSourcedRoleInst(NormalizerNamed):

    @property
    def config_path(self):
        return ['roles', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'id'



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           NexusRolesPrivManageRootNormer(self), *args,
           default_merge_vars=[
             'smabot_sonatype_manage_nexus_roles_and_privileges_args_defaults',
             'smabot_sonatype_manage_nexus_roles_and_privileges_args_extra_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_sonatype_manage_nexus_roles_and_privileges_args'

