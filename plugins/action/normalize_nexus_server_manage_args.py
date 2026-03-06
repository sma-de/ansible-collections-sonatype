
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import copy
import collections

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


class NexusServerConfigRootNormer(NormalizerBase):

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
          WaitServerReadyNorm(pluginref),
          NormInitSetup(pluginref),
          (LicenseNormer, True),
          (NormBlobStores, True),
          (NormCleanupPolicies, True),
          (NormRepos, True),
          (NormUsers, True),
          (NormRolesAndPrivileges, True),
          (NormCheckLoginCreds, True),
        ]

        super(NexusServerConfigRootNormer, self).__init__(pluginref, *args, **kwargs)


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


class LicenseNormer(NormalizerBase):

    NORMER_CONFIG_PATH = ['license']

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )
 
        super(LicenseNormer, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    @property
    def simpleform_key(self):
        return 'license'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ena = my_subcfg.get('enabled', None)
        c = my_subcfg['config']

        if ena is None:
            ena = bool(my_subcfg.get('license', None)) or bool(c)
            my_subcfg['enabled'] = ena

        if not my_subcfg['enabled']:
            return my_subcfg

        setdefault_none(c, 'state', 'present')

        if my_subcfg.get('license', None):
            c['license'] = my_subcfg['license']

        return my_subcfg



class NormBlobStores(NormalizerBase):

    NORMER_CONFIG_PATH = ['blobstores']

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## use global hide_secrets settings for subrole cfg,
        ## if not explicitly overridden
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'hide_secrets', pcfg['hide_secrets'])

        ## we already expanded vardir for this role,
        ## no reason to waste any energy doing this again for sub role
        my_subcfg['skip_vardir_expand'] = True

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        ## check if given config removes stuff, if so make a
        ## smaller subcfg without any removes
        st_root = (my_subcfg.get('blobstores', None) or {}).get(
          'stores', None
        ) or {}

        st_no_rm = {}
        any_changed = False

        for k, v in st_root.items():
            if not v:
                continue

            v_changed = False
            vc = copy.deepcopy(v)

            exclusive = vc.get('exclusive', False)

            if exclusive:
                ## in no-remove copy-cfg exclusive must always be false
                vc['exclusive'] = False
                v_changed = True
                any_changed = True

            st_def_state = (vc.get('store_defaults', None) or {}).get(
              'state', ''
            )

            keep_stores = {}

            ## check all stores for this type for keepers and
            ## remove deletes from this keepers-only cfg
            typed_substores = vc.get('stores', None) or {}
            for kk in list(typed_substores.keys()):
                vv = typed_substores[kk]
                vv_cfg = vv

                if not isinstance(vv_cfg, collections.abc.Mapping):
                    ## assume vv being simple string shortform
                    vv_cfg = {}

                vv_state = (vv_cfg.get('config', None) or {}).get(
                  'ansible_state', None
                ) or st_def_state

                if vv_state == 'absent':
                    ## remove removal request for this cfg
                    typed_substores.pop(kk)
                    v_changed = True
                    any_changed = True
                else:
                    keep_stores[kk] = vv

            if keep_stores:
                ## in no-remove copy-cfg we only care about blobstore
                ## types with at least one store to keep/create
                st_no_rm[k] = vc

        if any_changed:
            my_subcfg['blobstores'].pop('stores')
            keeper_cfg = copy.deepcopy(my_subcfg)

            my_subcfg['blobstores']['stores'] = st_root
            keeper_cfg['blobstores']['stores'] = st_no_rm

            pcfg = self.get_parentcfg(cfg, cfgpath_abs)

            setdefault_none(pcfg, '_export_cfgs', {}).update(
              blobstores_no_removes = keeper_cfg
            )

        return my_subcfg



class NormInitSetup(NormalizerBase):

    @property
    def config_path(self):
        return ['nexus_initial_setup']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## use global hide_secrets settings for subrole cfg,
        ## if not explicitly overridden
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'hide_secrets', pcfg['hide_secrets'])

        ## we already expanded vardir for this role,
        ## no reason to waste any energy doing this again for sub role
        my_subcfg['skip_vardir_expand'] = True

        return my_subcfg



class NormRepos(NormalizerBase):

    NORMER_CONFIG_PATH = ['repositories']

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## use global hide_secrets settings for subrole cfg,
        ## if not explicitly overridden
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'hide_secrets', pcfg['hide_secrets'])

        ## we already expanded vardir for this role,
        ## no reason to waste any energy doing this again for sub role
        my_subcfg['skip_vardir_expand'] = True

        return my_subcfg



class NormCleanupPolicies(NormalizerBase):

    NORMER_CONFIG_PATH = ['cleanup_policies']

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## use global hide_secrets settings for subrole cfg,
        ## if not explicitly overridden
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'hide_secrets', pcfg['hide_secrets'])

        ## we already expanded vardir for this role,
        ## no reason to waste any energy doing this again for sub role
        my_subcfg['skip_vardir_expand'] = True

        return my_subcfg



class NormUsers(NormalizerBase):

    NORMER_CONFIG_PATH = ['users']

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## use global hide_secrets settings for subrole cfg,
        ## if not explicitly overridden
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'hide_secrets', pcfg['hide_secrets'])

        ## we already expanded vardir for this role,
        ## no reason to waste any energy doing this again for sub role
        my_subcfg['skip_vardir_expand'] = True

        return my_subcfg


class NormRolesAndPrivileges(NormalizerBase):

    NORMER_CONFIG_PATH = ['roles_and_privileges']

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## use global hide_secrets settings for subrole cfg,
        ## if not explicitly overridden
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'hide_secrets', pcfg['hide_secrets'])

        ## we already expanded vardir for this role,
        ## no reason to waste any energy doing this again for sub role
        my_subcfg['skip_vardir_expand'] = True

        return my_subcfg


class NormCheckLoginCreds(NormalizerBase):

    NORMER_CONFIG_PATH = ['check_login_creds']

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## use global hide_secrets settings for subrole cfg,
        ## if not explicitly overridden
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        setdefault_none(my_subcfg, 'hide_secrets', pcfg['hide_secrets'])

        ## we already expanded vardir for this role,
        ## no reason to waste any energy doing this again for sub role
        my_subcfg['skip_vardir_expand'] = True

        return my_subcfg



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           NexusServerConfigRootNormer(self), *args,
           default_merge_vars=[
             'smabot_sonatype_manage_nexus_server_args_defaults',
             'smabot_sonatype_manage_nexus_server_args_extra_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_sonatype_manage_nexus_server_args'

