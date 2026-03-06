
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import collections
import copy
import datetime
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

    SECRET_KEYS = {
      'secretAccessKey': None,
    }


    CM_TYPE_CHANGE = {
      'blobgroup_migrate': True,
      'recreate': True,
    }


    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        tmp.update({
          'store_type': (list(string_types), 'file', ['file', 's3']),
          'blobstores': ([collections.abc.Mapping]),

          'store_defaults': ([collections.abc.Mapping, type(None)], None),

          ## note: only does matter when type == 'file'
          'keep_default': ([bool], True),

          'state': (list(string_types), 'present', ['present', 'absent']),
          'exclusive': ([bool], False),
        })

        return tmp


    def _create_store(self, cfg_store, store_type,
        state_new, state_by_name, parent_grp=None
    ):
        sid = cfg_store['name']

        ## drop non-upstream keys not needed for this create-new usecase
        for x in ['assume_changed', 'change_method', 'group_down', 'change_method_args']:
            cfg_store.pop(x, None)

        self.create_nexus_blobstore(store_type, cfg_store)
        res = self.read_nexus_blobstore_config(store_type, cfg_store)

        if parent_grp:
            parent_grp['members'].append(cfg_store['name'])
            self.update_nexus_blobstore_group_config(parent_grp)

            res['parent_group'] = parent_grp

        res['created_new'] = True
        res['change_state'] = 'created'
        state_new[sid] = res
        state_by_name[sid] = res


    def _cmp_attr_typed_s3(self, cur_key, eqres_orig, cfg_top=None,
        **kwargs
    ):
        ##
        ## note: it is impossible to properly compare s3 access secrets
        ##   as nexus properly secures them after they are set once
        ##   during blobstore creation and there is now way to read
        ##   current set secret back (in json api responses we get
        ##   dummy placeholder values)
        ##
        secret_keys_s3 = {
          'secretAccessKey': None,
        }

        if cur_key not in secret_keys_s3:
            return eqres_orig

        ##
        ## note.2: on default we assume secrets unchanged except
        ##   given user config explicitly requests otherwise
        ##
        assume_changed = cfg_top.get('assume_changed', None)

        if not assume_changed:
            return True  ## force no diff

        if not isinstance(assume_changed, collections.abc.Mapping):
            ## assume simple bool, meaning all secret keys should
            ## be assumed changed here
            return False  ## force diff

        ## final case: assume all secret keys changed which are
        ## keys in given assume_changed mapping
        return not assume_changed.get(cur_key, False)


    def _get_diff_recv(self, cfg_cur, ex_cur, **kwargs):
        ignore_keys = {}

        if kwargs.get('toplvl', True):
            ignore_keys = {
              'assume_changed': None,
              'change_method': None,
              'change_method_args': None,
              'group_down': None,
              'name': None,
            }

            kwargs.update(toplvl=False, cfg_top=cfg_cur, ex_top=ex_cur)

        is_map = True

        if isinstance(cfg_cur, list):
            itx = range(0, len(cfg_cur))
            is_map = False
        elif isinstance(cfg_cur, collections.abc.Mapping):
            ## assume map on default
            itx = cfg_cur.keys()
        else:
            return {
              'old': ex_cur, 'new': cfg_cur,
            }

        ##display.vvv(
        ##   "NEXUS_MANAGE_BLOBSTORES :: currently compare complex user"\
        ##   " config:\n{}\n\nwith existing server config:\n{}".format(
        ##       json.dumps(cfg_cur, indent=2),
        ##       json.dumps(ex_cur, indent=2),
        ##   )
        ##)

        cur_diff = {}

        for x in itx:
            if x in ignore_keys:
                continue

            v = cfg_cur[x]
            vo = ex_cur[x]

            if isinstance(v, list):
                v = sorted(v)

            if isinstance(vo, list):
                vo = sorted(vo)

            fn_cmp = getattr(self,
              '_cmp_attr_typed_' + kwargs['store_type'], None
            )

            if fn_cmp:
                if fn_cmp(x, v == vo, **kwargs):
                    # no diff here => noop
                    continue

            elif v == vo:
                # no diff here => noop
                continue

            k = x

            if not is_map:
                k = "[{}]".format(x)

            if isinstance(v, collections.abc.Mapping) \
              and isinstance(vo, collections.abc.Mapping):
                ## both are mapping, recurse down as mapping
                cur_diff_x = self._get_diff_recv(v, vo, **kwargs)
            elif isinstance(v, list) and isinstance(vo, list):
                ## both are lists, recurse down as lists
                cur_diff_x = self._get_diff_recv(v, vo, **kwargs)
            else:
                ## simple values or incompatible collection types,
                ## dont recurse
                if k in self.SECRET_KEYS:
                    ## hide secret values, assume that nexus already
                    ## obfuscate old values
                    v = '<< REDACTED >>'

                cur_diff_x = {'old': vo, 'new': v}

            if cur_diff_x:
                cur_diff[k] = cur_diff_x

        return cur_diff


    def _compare_stores(self, cfg_store, ex_store, store_type, state_updated):
        ex_store = copy.deepcopy(ex_store)
        ex_store['type'] = ex_store.pop('metadata').get('type').lower()

        cfg_store = copy.deepcopy(cfg_store)
        cfg_store['type'] = store_type.lower()

        diff = self._get_diff_recv(cfg_store, ex_store, store_type=store_type)

        if diff:
            state_updated[cfg_store['name']] = {'diff': diff}
            return True

        return False


    def _update_cm_mod_replacement_store(self, store_type, cfg_store,
      ex_store, **kwargs
    ):
      cfg_store = copy.deepcopy(cfg_store)

      ## optionally apply store_config_mods if there are any defined
      mtypes = ['attribute_suffix_alternate']

      for k, v in (kwargs.get('store_config_mods', None) or {}).items():
          display.vvv(
             "NEXUS_MANAGE_BLOBSTORES :: apply blobstore"\
             " config mod '{}':\n{}".format(k, json.dumps(v, indent=2))
          )

          vt = v['modtype']

          if vt == 'attribute_suffix_alternate':
              ## get config and existing value for attribute
              src_map = ex_store
              tgt_map = cfg_store

              kc = v['key'].split('.')

              for x in kc[:-1]:
                  src_map = src_map[x]
                  tgt_map = tgt_map[x]

              val_cfg  = tgt_map[kc[-1]]
              val_real = src_map[kc[-1]]

              ##if val_cfg == val_real:
              if True:
                  ## if real value and config set value are identical we
                  ## need to alternate, otherwise assume real value is 
                  ## currently already alternated version, so keep
                  ## original config setting then
                  tgt_map[kc[-1]] = val_cfg + v['suffix']

              continue

          ansible_assert(False,
            "unsupported modtype '{}' for given store_config_mod '{}',"\
            " must be one of these: {}".format(vt, k, mtypes)
          )

      return cfg_store


    def _update_cm_blobgroup_migrate(self, store_type, cfg_store,
        ex_store, **kwargs
    ):
        display.vv(
           "NEXUS_MANAGE_BLOBSTORES :: run special blobstore"\
           " update change method 'blobgroup_migrate' ..."
        )

        ##if ex_store['metadata']['blobCount'] == 0:
        ##    ## for simple store currently empty cases we can fallback
        ##    ## here to recreate method
        ##    return self._update_cm_recreate(store_type, cfg_store, ex_store)

        ##
        ## blobstore not empty, so we must take care that existing data
        ## survives and using repos are still serveable, use blobstore
        ## groups for this, see also here:
        ##   https://help.sonatype.com/en/blob-stores.html#moving-a-blob-store
        ##
        ## be aware that this method might change the kind of blobstore
        ## from a simple blobstore to a blobstore group with one blobstore
        ## in it if original is not already a blobstore group
        ##
        ## this method should not be mixed when your setup already
        ## uses advanced blobstore group stuff
        ##

        ## check if original blobstore is already blobstore group
        stname_in_grp = ex_store['name']
        bgrp_name = cfg_store['name']
        bgrp = self.get_nexus_blobstore_parent_group(stname_in_grp)

        if not bgrp:
            ## convert original blobstore to blobstore group
            stname_in_grp = bgrp_name +'-old-' + str(
              datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y%m%d-%H%M%S"
              )
            )

            self.convert_nexus_blobstore_to_group(
              bgrp_name, stname_in_grp
            )

            bgrp = self.read_nexus_blobstore_group_config(cfg_store)

        if bgrp['fillPolicy'] != 'writeToFirst':
            ## set write policy to first only
            bgrp['fillPolicy'] = 'writeToFirst'
            bgrp['name'] = bgrp_name

            self.update_nexus_blobstore_group_config(bgrp)
            bgrp = self.read_nexus_blobstore_group_config(cfg_store)

        ## create changed store settings as new store
        ## (we need some kind of name suffix here to avoid name clashes)
        cfg_store['name'] += '-' + str(
          datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d-%H%M%S"
          )
        )

        ##
        ## note: this will probably fail because nexus does not allow
        ##   multiple blobstores using the same s3 bucket as backend
        ##   and will validate against it, so one would need have a
        ##   s3-proxy middleware which supports having two different
        ##   bucket names pointing to the same backend (might be
        ##   possible with e.g. zenko), another possibility might be
        ##   to apply nginx reverse proxy url-rewriting tricks,
        ##   but I think aws-sigv4 make this impossible
        ##
        cfg_store = self._update_cm_mod_replacement_store(
          store_type, cfg_store, ex_store, **kwargs
        )

        self.create_nexus_blobstore(store_type, cfg_store)

        ## add new store to blobstore group
        bgrp['members'].append(cfg_store['name'])
        bgrp['name'] = bgrp_name
        self.update_nexus_blobstore_group_config(bgrp)

        ## "deactivate" original store with special admin task
        self.run_nexus_adhoc_task({
          "type": "blobstore.group.memberRemoval",
          "name": "test-api-create-task34",
          "properties": {
            "fromGroup": bgrp_name,
            "memberToRemove": stname_in_grp,
          },
        })

        ## delete original blobstore
        ## TODO: do we need to remove it here explicitly
        ##   or does the task handle this already
        ##self.remove_nexus_blobstore(stname_in_grp)


    ##
    ## note: in principle one could extend this to method which
    ##   also works with non empty blobstores relying on nexus
    ##   default soft-delete, which would work like this:
    ##
    ##     -> delete all repos of blobstore (content only soft-deletes)
    ##     -> delete blobstore itself (content only soft-deletes)
    ##     -> recreate blobstore with potentially changed
    ##        config (but same path/bucket)
    ##     -> recreate repo(s)
    ##
    ##     -> run nexus data repair tasks:
    ##          https://help.sonatype.com/en/verify-and-repair-data-consistency-tasks.html
    ##
    ##   but there some issues with this approach:
    ##
    ##     -> currently repair tasks are simply broken and do not work properly
    ##     -> very complex and multi stepped, probably wonky and unreliable
    ##     -> can (will??) take a lot of time, much more than what is
    ##        acceptable for just changing blobstore config a bit around
    ##
    def _update_cm_recreate(self, store_type, cfg_store, ex_store, **kwargs):
        display.vv(
           "NEXUS_MANAGE_BLOBSTORES :: run special blobstore"\
           " update change method 'recreate' ..."
        )

        ansible_assert(ex_store['metadata']['blobCount'] == 0,
          "Updating blobstore by recreation change_method can only"\
          " be safely done, when the orignal blobstore is empty"
        )

        ## recreate blobstore with new settings
        self.remove_nexus_blobstore(cfg_store['name'])

        cfg_store = self._update_cm_mod_replacement_store(
          store_type, cfg_store, ex_store, **kwargs
        )

        self.create_nexus_blobstore(store_type, cfg_store)


    def _handle_type_diff(self, store_type, cfg_store, ex_store, store_map):
        if not ex_store:
            ## no corresponding store does exist yet => noop
            return (ex_store, None)

        if ex_store['metadata']['type'].lower() == store_type:
            ## no type diff between cfg and existing store => noop
            return (ex_store, None)

        ## check if we have a change method which can handle type changes
        cm_okay = self.CM_TYPE_CHANGE.get(
          cfg_store.get('change_method', None), None
        )

        if cm_okay and ex_store['metadata']['type'].lower() != 'group':
            ## we have a type diff, but change method can handle it
            return (ex_store, None)

        gdown = cfg_store.get('group_down', False)

        ansible_assert(
          ex_store['metadata']['type'].lower() == 'group' and gdown,
          "cannot auto convert store type for already existing"\
          " blobstore '{}' from '{}' to '{}'".format(ex_store['name'],
              ex_store['metadata']['type'].lower(), store_type
          )
        )

        ## final cases, special handling when we have a type diff
        ## and existing store is actually a group
        bgrp = self.read_nexus_blobstore_group_config(ex_store)

        if len(bgrp['members']) == 0:
            ## make current cfg repo groups only child, basically a NEW case
            return (None, bgrp)

        else:
            ##ansible_assert(len(bgrp['members']) == 1,
            ##  "cannot auto convert store type for already existing"\
            ##  " blobstore '{}' from '{}' to '{}'".format(
            ##     ex_store['name'], ex_store['metadata']['type'].lower(),
            ##     store_type
            ##  )
            ##)

            ## instead of diffing to parent group,
            ## use the single child of the group as diff
            ## object to current cfg store
            res = {'metadata': store_map[bgrp['members'][0]]}
            res.update(self.read_nexus_blobstore_config(
               res['metadata']['type'], res['metadata']
            ))

            return (res, None)


    def _update_store(self, cfg_store, store_type, ex_store,
        state_updated, state_by_name
    ):
        cm = cfg_store.pop('change_method', None)
        cm_args = cfg_store.pop('change_method_args', None) or {}
        cm_fn = None

        if cm:
            cm_fn = getattr(self, '_update_cm_' + cm, None)

            ansible_assert(cm_fn,
              "Unsupported change_method '{}'".format(cm)
            )

        ## drop non-upstream keys not needed for this create-new usecase
        for x in ['assume_changed', 'group_down']:
            cfg_store.pop(x, None)

        cfg_store = copy.deepcopy(cfg_store)
        uid = cfg_store['name']

        res = copy.deepcopy(cfg_store)
        res.update(state_updated[uid])

        try:
            if cm_fn:
                display.vv(
                   "NEXUS_MANAGE_BLOBSTORES :: blobstore update found"\
                   " necessary for '{}', will use special change method"\
                   " '{}'".format(uid, cm)
                )

                cm_fn(store_type, cfg_store, ex_store, **cm_args)
            else:
                display.vv(
                   "NEXUS_MANAGE_BLOBSTORES :: blobstore update found"\
                   " necessary for '{}', will use default api"\
                   " method".format(uid, cm)
                )

                self.update_nexus_blobstore(store_type, cfg_store)

            res.update(self.read_nexus_blobstore_config(
              store_type, cfg_store
            ))

        except Exception as e:
            res['wanted_state'] = 'updated'
            state_updated.pop(uid)

            e.fail_details = res
            raise e

        res['updated'] = True
        res['change_state'] = 'updated'
        state_updated[uid] = res
        state_by_name[uid] = res


    def _delete_store(self, cfg_store, state_removed, state_by_name):
        self.remove_nexus_blobstore(cfg_store['name'])

        cfg_store['removed'] = True
        cfg_store['change_state'] = 'removed'
        state_removed[cfg_store['name']] = cfg_store
        state_by_name[cfg_store['name']] = cfg_store


    def run_specific(self, result):
        exclusive = self.get_taskparam('exclusive')
        keep_default = self.get_taskparam('keep_default')

        st_type = self.get_taskparam('store_type')
        ans_state_default = self.get_taskparam('state')
        cfg_stores = self.get_taskparam('blobstores')

        store_defaults = self.get_taskparam('store_defaults') or {}

        ## query all existing stores for given type
        display.vv(
           "NEXUS_MANAGE_BLOBSTORES :: query existing blobstores"\
           " from nexus ..."
        )

        existing_stores = self.get_nexus_blobstores(return_as_map=True)

        display.vvv(
           "NEXUS_MANAGE_BLOBSTORES :: all blobstores currently existing on"\
           " nexus:\n{}".format(json.dumps(existing_stores, indent=2))
        )

        state_by_name = {}
        state_new = {}
        state_updated = {}
        state_unchanged = {}
        state_removed = {}
        state_failed = {}

        absent_stores = {}

        ## loop through existing stores + cfg mapping parameter and
        ## determine per stores: create/update/nochange/delete
        for uk, uv in cfg_stores.items():
            display.vv(
               "NEXUS_MANAGE_BLOBSTORES :: handle config blobstore"\
               " '{}' ...".format(uk)
            )

            uv = merge_dicts(copy.deepcopy(store_defaults), uv)

            setdefault_none(uv, 'ansible_state', ans_state_default)
            uv_ansstate = uv.pop('ansible_state')

            ex_store = existing_stores.pop(uv['name'], None)

            try:
                if uv_ansstate == 'present':
                    if ex_store:
                        ex_store = {'metadata': ex_store}

                        ex_store.update(self.read_nexus_blobstore_config(
                           ex_store['metadata']['type'], ex_store['metadata']
                        ))

                    ex_store, pgrp = self._handle_type_diff(st_type,
                      uv, ex_store, existing_stores
                    )

                    if not ex_store:
                        ## store is new
                        display.vv(
                           "NEXUS_MANAGE_BLOBSTORES :: ... store"\
                           " is new, create it"
                        )

                        self._create_store(uv, st_type,
                          state_new, state_by_name, parent_grp=pgrp
                        )

                        continue

                    if self._compare_stores(uv, ex_store, st_type, state_updated):
                        ## config store is somehow different to exisiting store
                        display.vv(
                           "NEXUS_MANAGE_BLOBSTORES :: ... store exist but"\
                           " given config differs, update them"
                        )

                        self._update_store(uv, st_type, ex_store,
                           state_updated, state_by_name
                        )

                        continue

                    ex_store['unchanged'] = True
                    ex_store['change_state'] = 'unchanged'
                    state_unchanged[ex_store['name']] = ex_store
                    state_by_name[ex_store['name']] = ex_store
                    continue

                ## ans_state == absent, ensure user does not exist on nexus
                if ex_store:
                    ex_store['remove_reason'] = 'explicitly_absented'
                    absent_stores[uk] = ex_store

            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = ex_store or {'name': uv['name']}

                tmp['failed'] = True
                tmp['change_state'] = 'failed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed[tmp['name']] = tmp
                state_by_name[tmp['name']] = tmp

        if exclusive and existing_stores:
            ## in exclusive mode also kill all stores not
            ## explicitly mentionend by given config
            display.vv(
               "NEXUS_MANAGE_BLOBSTORES :: exclusive mode active,"\
               " remove also all existing blobstores not mentioned by"\
               " given config ..."
            )

            exclusive_rm = {}

            for k, v in existing_stores.items():
                if v['type'].lower() != st_type:
                   ## we always only care about stores with the
                   ## current config type and only look at other
                   ## types for name clashes
                   continue

                if v['name'] == 'default' and keep_default:
                    display.vv(
                       "NEXUS_MANAGE_BLOBSTORES :: keep default"\
                       " blobstore although it is not part of exclusive set"\
                       " because special 'keep_default' flag is on ..."
                    )

                    continue

                state_unchanged.pop(v['name'], None)

                v['remove_reason'] = 'exclusive_mode'
                absent_stores[k] = v
                exclusive_rm[k] = v

            display.vvv(
               "NEXUS_MANAGE_BLOBSTORES :: existing stores additionally"\
               " removed because of exclusive mode:\n{}".format(
                  json.dumps(exclusive_rm, indent=2)
               )
            )


        ## remove stores which should be removed
        for uk, uv in absent_stores.items():
            display.vv(
               "NEXUS_MANAGE_BLOBSTORES :: removing existing"\
               " blobstore '{}' ...".format(uk)
            )

            try:
                self._delete_store(uv, state_removed, state_by_name)
            except Exception as e:
                tmp = getattr(e, 'fail_details', None)

                if not tmp:
                    tmp = uv

                tmp['failed'] = True
                tmp['change_state'] = 'failed'
                tmp['wanted_state'] = 'removed'

                tmp['error_type'] = str(type(e))
                tmp['error_msg'] = str(e)

                state_failed[tmp['name']] = tmp
                state_by_name[tmp['name']] = tmp

        ## export final state / changes of this call
        result['blobstores'] = {
          'by_change': {
            'new': state_new,
            'updated': state_updated,
            'unchanged': state_unchanged,
            'removed': state_removed,
            'failed': state_failed,
          },

          'by_name': state_by_name,
        }

        if state_failed:
            result['failed'] = True
            result['msg'] = "Some kind of unexpected error happend"\
                            " while modifying these stores: {}".format(
                                list(state_failed.keys())
                            )

        elif state_new or state_updated or state_removed:
            result['changed'] = True

        return result

