
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


class NexusCleanupPolManageRootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (ConnectionNormer, True),
          NormCleanupPolsTopLvl(pluginref),
        ]

        super(NexusCleanupPolManageRootNormer, self).__init__(pluginref, *args, **kwargs)


class ConnectionNormer(SecureConnectionNormer):

    NORMER_CONFIG_PATH = ['connection']

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(pluginref, *args,
            srvtype_default='sonanexus',
            config_path=self.NORMER_CONFIG_PATH, **kwargs
        )


class NormCleanupPolsTopLvl(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'exclusive', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormCleanupPolDefaults(pluginref),
          NormCleanupPolInst(pluginref),
        ]

        super(NormCleanupPolsTopLvl, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['cleanup_policies']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        my_pols = {}

        for k, v in my_subcfg['policies'].items():
           my_pols[k] = v['config']

        if my_pols:
            exp_cfg = setdefault_none(my_subcfg, '_export_cfgs', {})

            exp_cfg['policy_manage'] = {
              'policies': my_pols,
              'policy_defaults': my_subcfg['policy_defaults']['config'],
              'state': my_subcfg['policy_defaults']['state'],
              'exclusive': my_subcfg['exclusive'],
            }

        return my_subcfg


class NormCleanupPolDefaults(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'state', DefaultSetterConstant('present')
        )

        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        super(NormCleanupPolDefaults, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['policy_defaults']



class NormCleanupPolInst(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        self._add_defaultsetter(kwargs,
          'description', DefaultSetterConstant(None)
        )

        super(NormCleanupPolInst, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['policies', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']
        c['name'] = my_subcfg['name']

        tmp = my_subcfg.get('format', None)

        if tmp:
            c['format'] = tmp

        tmp = my_subcfg['description']

        if tmp:
            c['notes'] = tmp

        return my_subcfg



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           NexusCleanupPolManageRootNormer(self), *args,
           default_merge_vars=[
             'smabot_sonatype_manage_nexus_cleanup_policy_args_defaults',
             'smabot_sonatype_manage_nexus_cleanup_policy_args_extra_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_sonatype_manage_nexus_cleanup_policy_args'

