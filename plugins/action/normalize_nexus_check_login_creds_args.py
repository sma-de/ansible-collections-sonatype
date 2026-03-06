
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


class NexusCheckLoginRootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs,
          'optional', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (ConnectionNormer, True),
          NormCredSources(pluginref),
        ]

        super(NexusCheckLoginRootNormer, self).__init__(pluginref, *args, **kwargs)


class ConnectionNormer(SecureConnectionNormer):

    NORMER_CONFIG_PATH = ['connection']

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(pluginref, *args,
            srvtype_default='sonanexus',
            config_path=self.NORMER_CONFIG_PATH, **kwargs
        )


class NormCredSources(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormCredSrcInst(pluginref),
        ]
 
        super(NormCredSources, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['credential_sources']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        ## convert given cred source map to prio sorted list
        prio_set = set()
        prio_map = {}

        for k,v in my_subcfg['sources'].items():
            prio_set.add(v['priority'])
            prio_map.setdefault(v['priority'], []).append(v)

        prio_lst = []
        for p in sorted(prio_set):
          prio_lst += prio_map[p]

        my_subcfg['_export_configs'] = {
          'cred_sources_by_prio': prio_lst,
        }

        return my_subcfg



class NormCredSrcInst(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'priority', DefaultSetterConstant(0)
        )

        self._add_defaultsetter(kwargs,
          'type', DefaultSetterConstant('pwfile')
        )

        self._add_defaultsetter(kwargs,
          'optional', DefaultSetterConstant(False)
        )

        super(NormCredSrcInst, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['sources', SUBDICT_METAKEY_ANY]

    @property
    def simpleform_key(self):
        return 'path'

    @property
    def name_key(self):
        return 'mapkey'
 

    def _handle_type_special_pwfile(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'user', 'admin')


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        mt = my_subcfg['type']

        mt_fn = getattr(self, '_handle_type_special_' + mt, None)

        if mt_fn:
            mt_fn(cfg, my_subcfg, cfgpath_abs)

        return my_subcfg



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           NexusCheckLoginRootNormer(self), *args,
           default_merge_vars=[
             'smabot_sonatype_nexus_check_login_creds_args_defaults',
             'smabot_sonatype_nexus_check_login_creds_args_extra_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_sonatype_nexus_check_login_creds_args'

