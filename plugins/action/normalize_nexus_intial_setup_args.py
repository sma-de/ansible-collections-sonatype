
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


class NexusInitSetupRootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs,
          'server_restart_notify', DefaultSetterConstant('')
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (ConnectionNormer, True),
          NormInitSetup(pluginref),
          WaitServerReadyNorm(pluginref),
        ]

        super(NexusInitSetupRootNormer, self).__init__(pluginref, *args, **kwargs)


class ConnectionNormer(SecureConnectionNormer):

    NORMER_CONFIG_PATH = ['connection']

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(pluginref, *args,
            srvtype_default='sonanexus',
            config_path=self.NORMER_CONFIG_PATH, **kwargs
        )


class WaitServerReadyNorm(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )
 
        self._add_defaultsetter(kwargs,
          'taskname', DefaultSetterConstant(
             "ensure nexus server is properly booted and"\
             " reachable (timeout: 5min)"
          )
        )
 
        super(WaitServerReadyNorm, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['wait_server_ready']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']
        url = c.get('url', None)

        if not url:
            ## first, check if this config has connection set,
            ## if so, get url from there
            pcfg = self.get_parentcfg(cfg, cfgpath_abs)
            url = (pcfg.get('connection', None) or {}).get('url', None)

            if not url:
                ## as fallback try to get url from potentially
                ## set ansible vars
                test_vars = ['auth_nexus_url', 'auth_sonatypenx_url',
                  'auth_url_sonanexus', 'auth_url'
                ]

                for x in test_vars:
                    url = self.pluginref.get_ansible_var(x, default=None)

                    if url:
                        break

            c['url'] = url

        return my_subcfg


class NormInitSetup(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )
 
        self._add_defaultsetter(kwargs,
          'pw_gen', DefaultSetterConstant({})
        )
 
        super(NormInitSetup, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['initial_setup']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']
        my_subcfg['password_preset'] = bool(c.get('admin_password', False))

        pgen = my_subcfg['pw_gen']
        setdefault_none(pgen, 'length', 40)

        return my_subcfg



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           NexusInitSetupRootNormer(self), *args,
           default_merge_vars=[
             'smabot_sonatype_nexus_initial_setup_args_defaults',
             'smabot_sonatype_nexus_initial_setup_args_extra_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_sonatype_nexus_initial_setup_args'

