
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


class NexusBlobStoreManageRootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (ConnectionNormer, True),
          NormBlobStoresTopLvl(pluginref),
        ]

        super(NexusBlobStoreManageRootNormer, self).__init__(pluginref, *args, **kwargs)


class ConnectionNormer(SecureConnectionNormer):

    NORMER_CONFIG_PATH = ['connection']

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(pluginref, *args,
            srvtype_default='sonanexus',
            config_path=self.NORMER_CONFIG_PATH, **kwargs
        )


class NormBlobStoresTopLvl(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormBlobStoresFile(pluginref),
          NormBlobStoresS3(pluginref),
        ]

        super(NormBlobStoresTopLvl, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['blobstores']


class NormBlobStoresBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'exclusive', DefaultSetterConstant(False)
        )

        super(NormBlobStoresBase, self).__init__(pluginref, *args, **kwargs)


    def _get_store_type_id(self, cfg, my_subcfg, cfgpath_abs):
        return cfgpath_abs[-1]

    def _get_store_manage_export_cfg(self, stores, cfg,
      my_subcfg, cfgpath_abs
    ):
        return {
          'store_type': self._get_store_type_id(cfg, my_subcfg, cfgpath_abs),
          'blobstores': stores,
          'store_defaults': my_subcfg['store_defaults']['config'],
          'state': my_subcfg['store_defaults']['state'],
          'exclusive': my_subcfg['exclusive'],
        }


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        my_stores = {}

        for k, v in my_subcfg['stores'].items():
           my_stores[k] = v['config']

        if my_stores or my_subcfg['exclusive']:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

            exp_cfg = setdefault_none(setdefault_none(
               pcfg, '_export_cfgs', {}), 'store_manage', {}
            )

            exp_cfg[self._get_store_type_id(cfg, my_subcfg, cfgpath_abs)] =\
              self._get_store_manage_export_cfg(
                 my_stores, cfg, my_subcfg, cfgpath_abs
              )

        return my_subcfg


class NormBlobStoresDefaultsBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'state', DefaultSetterConstant('present')
        )

        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        super(NormBlobStoresDefaultsBase, self).__init__(pluginref, *args, **kwargs)


class NormBlobStoreInstBase(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'config', DefaultSetterConstant({})
        )

        super(NormBlobStoreInstBase, self).__init__(pluginref, *args, **kwargs)


class NormBlobStoreFileDefaults(NormBlobStoresDefaultsBase):

    @property
    def config_path(self):
        return ['store_defaults']


class NormBlobStoresFile(NormBlobStoresBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'keep_default', DefaultSetterConstant(True)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormBlobStoreFileDefaults(pluginref),
          NormBlobStoreFileInst(pluginref),
        ]

        super(NormBlobStoresFile, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['stores', 'file']

    def _get_store_manage_export_cfg(self, stores, cfg,
      my_subcfg, cfgpath_abs
    ):
        res = super()._get_store_manage_export_cfg(stores,
          cfg, my_subcfg, cfgpath_abs
        )

        res.update({
          'keep_default': my_subcfg['keep_default'],
        })

        return res


class NormBlobStoreFileInst(NormBlobStoreInstBase):

    @property
    def config_path(self):
        return ['stores', SUBDICT_METAKEY_ANY]

    @property
    def simpleform_key(self):
        return 'path'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']
        c['name'] = my_subcfg['name']

        p = my_subcfg.get('path', None)

        if p:
            c['path'] = p

        return my_subcfg



class NormBlobStoresS3(NormBlobStoresBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormBlobStoreS3Defaults(pluginref),
          NormBlobStoreS3Inst(pluginref),
        ]

        super(NormBlobStoresS3, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['stores', 's3']



class NormBlobStoreS3Defaults(NormBlobStoresDefaultsBase):

    @property
    def config_path(self):
        return ['store_defaults']


class NormBlobStoreS3Inst(NormBlobStoreInstBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormBlobStoreS3InstBucket(pluginref),
        ]

        super(NormBlobStoreS3Inst, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['stores', SUBDICT_METAKEY_ANY]

    @property
    def simpleform_key(self):
        return 'bucket'

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']
        c['name'] = my_subcfg['name']

        b = my_subcfg.get('bucket', None)

        if b:
            setdefault_none(c, 'bucketConfiguration', {}).update(bucket=b)

        con = my_subcfg.get('connection', None)

        if con:
            con_x = con.get('custom_endpoint', None)

            if con_x:
                setdefault_none(setdefault_none(c,
                  'bucketConfiguration', {}), 'advancedBucketConnection', {}
                ).update(endpoint=con_x)

            con_x = con.get('pathstyle_urls', None)

            if con_x:
                setdefault_none(setdefault_none(c,
                  'bucketConfiguration', {}), 'advancedBucketConnection', {}
                ).update(forcePathStyle=con_x)

        return my_subcfg


class NormBlobStoreS3InstBucket(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'region', DefaultSetterConstant('Default')
        )

        super(NormBlobStoreS3InstBucket, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['bucket']

    @property
    def simpleform_key(self):
        return 'name'



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           NexusBlobStoreManageRootNormer(self), *args,
           default_merge_vars=[
             'smabot_sonatype_manage_nexus_blobstore_args_defaults',
             'smabot_sonatype_manage_nexus_blobstore_args_extra_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_sonatype_manage_nexus_blobstore_args'

