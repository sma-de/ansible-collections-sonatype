
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

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import \
  get_subdict,\
  merge_dicts,\
  setdefault_none,\
  SUBDICT_METAKEY_ANY

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert


display = Display()



class NexusRepoManageRootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (ConnectionNormer, True),
          NormReposTopLvl(pluginref),
        ]

        super(NexusRepoManageRootNormer, self).__init__(pluginref, *args, **kwargs)


class ConnectionNormer(SecureConnectionNormer):

    NORMER_CONFIG_PATH = ['connection']

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(pluginref, *args,
            srvtype_default='sonanexus',
            config_path=self.NORMER_CONFIG_PATH, **kwargs
        )


class NormReposTopLvl(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'exclusive', DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs,
          'no_default_repos', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (NormRepoFormatDocker, True),
        ]

        super(NormReposTopLvl, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['repositories']


class NormRepoFormatBase(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'exclusive', DefaultSetterConstant(False)
        )

        super(NormRepoFormatBase, self).__init__(pluginref, *args, **kwargs)

    @property
    def name_key(self):
        return 'repo_format'


class NormRepoVarHostedBase(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'exclusive', DefaultSetterConstant(False)
        )

        super(NormRepoVarHostedBase, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['repo_types', 'hosted']

    @property
    def name_key(self):
        return 'repo_type'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        my_subcfg['repo_format'] = pcfg['repo_format']
        return my_subcfg

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        my_repos = {}

        for k, v in my_subcfg['repos'].items():
           my_repos[k] = v['config']

        pcfg_type = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=4)

        type_exclusive = my_subcfg['exclusive']
        fmt_exclusive = pcfg_type['exclusive']
        all_exclusive = pcfg['exclusive']

        exclusive = None
        exclude_ignore = {}

        if all_exclusive:
            exclusive = 'all'

            ## protect all and any repo mentioned in this
            ## config against kill by exclusion
            for k, v in pcfg['repo_formats'].items():
                for kk, vv in v['repo_types'].items():
                    for k3, v3 in vv['repos'].items():
                        exclude_ignore[k3] = True

        elif fmt_exclusive:
            exclusive = 'format'

            ## protect all format sibling repos mentioned in
            ## this config against kill by exclusion
            for k, v in pcfg_type['repo_types'].items():
                for kk, vv in vv['repos'].items():
                    exclude_ignore[kk] = True

        elif type_exclusive:
            exclusive = 'type'

        exp_cfg = setdefault_none(setdefault_none(
           pcfg, '_export_cfgs', {}), 'repo_manage', {}
        )

        sub_cfg_id = "{}/{}".format(
          my_subcfg['repo_format'], my_subcfg['repo_type']
        )

        exp_cfg[sub_cfg_id] = {
          'repo_format': my_subcfg['repo_format'],
          'repo_type': my_subcfg['repo_type'],
          'repositories': my_repos,
          'repo_defaults': my_subcfg['repo_defaults']['config'],
          'state': my_subcfg['repo_defaults']['state'],
          'exclusive': exclusive,
          'no_default_repos': pcfg['no_default_repos'],
          'exclusion_ignores': exclude_ignore,
        }

        return my_subcfg


class NormRepoDefaultsBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'state', DefaultSetterConstant('present')
        )

        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        super(NormRepoDefaultsBase, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['repo_defaults']


class NormRepoDefaultsTypeBase(NormRepoDefaultsBase):

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)
        my_subcfg = merge_dicts(
          copy.deepcopy(pcfg['repo_defaults']), my_subcfg
        )

        return my_subcfg


class NormRepoInstBase(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (NormRepoInstBlobStore, True),
        ]

        super(NormRepoInstBase, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['repos', SUBDICT_METAKEY_ANY]

    @property
    def simpleform_key(self):
        return 'blobstore'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']
        c['name'] = my_subcfg['name']

        return my_subcfg

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']
        b = my_subcfg.get('blobstore', None)

        if b:
            st = setdefault_none(c, 'storage', {})
            merge_dicts(st, b['config'])

        return my_subcfg


class NormRepoInstBlobStore(NormalizerBase):

    NORMER_CONFIG_PATH = ['blobstore']

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        super(NormRepoInstBlobStore, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    @property
    def simpleform_key(self):
        return 'name'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']
        c['blobStoreName'] = my_subcfg['name']
        return my_subcfg


class NormRepoFormatDockerDefaults(NormRepoDefaultsBase):
    pass


class NormRepoDockerHostedDefaults(NormRepoDefaultsTypeBase):
    pass


class NormRepoFormatDocker(NormRepoFormatBase):

    NORMER_CONFIG_PATH = ['repo_formats', 'docker']

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormRepoFormatDockerDefaults(pluginref),
          NormRepoTypeDockerHosted(pluginref),
        ]

        super(NormRepoFormatDocker, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH


class NormRepoTypeDockerHosted(NormRepoVarHostedBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormRepoDockerHostedDefaults(pluginref),
          NormRepoDockerHostedInst(pluginref),
        ]

        super(NormRepoTypeDockerHosted, self).__init__(pluginref, *args, **kwargs)


class NormRepoDockerHostedInst(NormRepoInstBase):
    pass



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           NexusRepoManageRootNormer(self), *args,
           default_merge_vars=[
             'smabot_sonatype_manage_nexus_repository_args_defaults',
             'smabot_sonatype_manage_nexus_repository_args_extra_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_sonatype_manage_nexus_repository_args'

