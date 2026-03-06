
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import copy
import collections
import json

from ansible.errors import \
  AnsibleAssertionError,\
  AnsibleOptionsError,\
  AnsibleError

####from ansible.module_utils._text import to_native
from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.smabot.base.plugins.module_utils.plugins.action_base import BaseAction
from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert
from ansible.utils.display import Display


display = Display()


class NexusBase(BaseAction):

    def __init__(self, *args, **kwargs):
        super(NexusBase, self).__init__(*args, **kwargs)
        self._api_usr_override = None
        self._api_pw_override = None
        self._blobstore_func_map = None
        self._repo_func_map = None


    @property
    def argspec(self):
        tmp = super(NexusBase, self).argspec

        tmp.update({
          MAGIC_ARGSPECKEY_META: {
             'mutual_exclusions': [
                ['api_token', 'api_username'],
                ['api_token', 'api_password'],
             ],
          },

          'api_url': {
            'type': list(string_types),
            'defaulting': {
               'ansvar': ['auth_nexus_url',
                  'auth_sonatypenx_url', 'auth_url_sonanexus',
                  'auth_url',
                ],
##         'env': '',
            },
          },

          'api_token': {
            'type': list(string_types),
            'defaulting': {
               'ansvar': [
                  'auth_nexus_token', 'auth_sonatypenx_token',
                  'auth_token_sonanexus', 'auth_token',
                ],
               'fallback': ''
            },
          },

          'api_username': {
            'type': list(string_types),
            'defaulting': {
               'ansvar': [
                  'auth_nexus_user', 'auth_sonatypenx_user',
                  'auth_user_sonanexus', 'auth_user',
                ],
               'fallback': ''
            },
          },

          'api_password': {
            'type': list(string_types),
            'defaulting': {
               'ansvar': [
                   'auth_nexus_pw', 'auth_sonatypenx_pw',
                  'auth_pw_sonanexus', 'auth_pw',
                ],
               'fallback': ''
            },
          },

          'validate_certs': {
            'type': [bool],
            'defaulting': {
               'ansvar': ['auth_nexus_certval', 'auth_sonatypenx_certval'],
               'fallback': True
            },
          },
        })

        return tmp

    @property
    def rest_api_version(self):
        return 1

    @property
    def rest_api_basepath(self):
        return "service/rest/v{}".format(self.rest_api_version)

    @property
    def nexus_url(self):
        return self.get_taskparam('api_url')

    @property
    def special_nexus_realms(self):
        return {
          'default_nexus_auth': 'NexusAuthenticatingRealm',
        }

    @property
    def nexus_url_restapi(self):
        return "{}/{}".format(self.nexus_url, self.rest_api_basepath)

    @property
    def nexus_auth_user(self):
        if self._api_usr_override:
            return self._api_usr_override

        return self.get_taskparam('api_username')

    @property
    def nexus_auth_pw(self):
        if self._api_pw_override:
            return self._api_pw_override

        return self.get_taskparam('api_password')

    @property
    def nexus_key_mappings_users(self):
        return {
          'userId': 'id',
        }


##    def get_server_client(self, re_auth=False, **kwargs):
##        if not self._gitlab_client or re_auth:
##
##            if not self._gitlab_client:
##                display.vvv("GitLabBase :: Initial client creation and authing")
##            else:
##                display.vvv("GitLabBase :: re-authing")
##
##            tmp = {
##              'url': self.gitlab_url,
##              'ssl_verify': self.get_taskparam('validate_certs'),
##              'private_token': self.gitlab_auth_token,
##              'api_version': 4
##            }
##
##            tmp.update(kwargs)
##            import gitlab
##            tmp = gitlab.Gitlab(**tmp)
##            tmp.auth()
##
##            self._gitlab_client = tmp
##
##        return self._gitlab_client


    def query_nexus_restapi(self, resource, auth=True, method=None,
        url_query=None, body=None, srcfile=None, fwargs=None, **kwargs
    ):
        ansible_assert(resource,
           "bad nexus_api query call, must provide an"\
           " non-empty resource path"
        )

        modargs = fwargs or {}

        if body or srcfile:
            method = method or 'POST'

            if body:
                modargs['body'] = body

                if isinstance(body, (list, collections.abc.Mapping)):
                    modargs.setdefault('body_format', 'json')

            else:
                modargs['src'] = srcfile

        if method:
            modargs['method'] = method

        url = self.nexus_url_restapi
        url_sfx = resource

        if url_sfx[0] != '/':
            url_sfx = '/' + url_sfx

        if url_query:
            url_sfx += '?'

            if isinstance(url_query, collections.abc.Mapping):
                tmp = []

                for k, v in url_query.items():
                    tmp.append("{}={}".format(k, v))

                url_sfx += '&'.join(tmp)
            else:
                ## assume preformatted string
                url_sfx += url_query

        modargs['url'] = url + url_sfx
        modargs['validate_certs'] = self.get_taskparam('validate_certs')

        passthrough_args = ['status_code', 'headers']

        for pa in passthrough_args:
            tmp = kwargs.pop(pa, None)

            if tmp:
                modargs[pa] = tmp

        if auth:
            # handle authing credentials when needed

            ## necessary, as nexus returns with 404 instead
            ## of 401 when auth is bad
            modargs['force_basic_auth'] = True

            pw_given = False
            token_given = False

            modkey_map = {
              'api_username': 'url_username',
              'api_password': 'url_password',
              'api_token': 'url_password',
            }

            for apk, apv in modkey_map.items():
                if modargs.get(apv, None):
                    ## if we already have a password or
                    ## user set, dont try setting it anymore
                    continue

                ## optionally allow calling method to
                ## overwrite used auth credentials
                tmp = kwargs.pop(apv, None)

                if not tmp:
                    if apk == 'api_username':
                        tmp = self.nexus_auth_user
                    elif apk == 'api_password':
                        tmp = self.nexus_auth_pw
                    else:
                        tmp = self.get_taskparam(apk)

                if tmp:
                    modargs[apv] = tmp

                    if apk == 'api_password':
                        pw_given = True
                    elif apk == 'api_token':
                        token_given = True

            if not pw_given and not token_given:
                e = AnsibleOptionsError(
                   "Nexus api rest call to '{}' needs authorisation,"\
                   " caller must either provide a password or a"\
                   " token".format(modargs['url'])
                )

                e.no_nexus_auth = True
                raise e

        return self.exec_module('ansible.builtin.uri',
            modargs=modargs, **kwargs
        )


    def get_system_license(self, **kwargs):
        tmp = self.query_nexus_restapi('system/license',
          status_code=[200, 402], **kwargs
        )

        if tmp['status'] in [402]:
            ## currently no licence installed
            return None

        return tmp['json']


    def set_system_license(self, nx_license, **kwargs):
        ##
        ## note: nx_license is a binary blob which makes parsing
        ##   it through the system a lot more complicated, we
        ##   expect it here input-wise to be safely encoded as base64
        ##
        ## note.2: as ansible / json / yaml are all more text-based
        ##   systems it is hard to handle binary here, actually we
        ##   atm dont now any way to safely pass the binary licence
        ##   directly to thr uri module, the best way we so far is
        ##   to copy the base64 as file to target and use target
        ##   shell commands for the binary conversion which should
        ##   be 100% reliable but also adds a lot of overhead
        ##
        tmpfile = None

        try:
            ## create tmpfile
            tmpfile = self.exec_module('ansible.builtin.tempfile',
               modargs={'state': 'file'},
            )

            ## make it secure
            self.exec_module('ansible.builtin.file',
               modargs={'mode': '600', 'path': tmpfile['path']},
            )

            ## fill remote tmpfile with decoded licence content
            self.exec_module('ansible.builtin.shell',
               modargs={'stdin': nx_license,
                 'cmd': "base64 --decode >> '{}'".format(tmpfile['path'])
               },
            )

            tmp = self.query_nexus_restapi('system/license',
              srcfile=tmpfile['path'], fwargs={
                'body_format': 'raw',
              }, headers={'Content-Type': 'application/octet-stream'},
              **kwargs
            )

        finally:
            if tmpfile:
                ## ensure tmpfile is deleted post operation if it exists
                self.exec_module('ansible.builtin.file',
                   modargs={'state': 'absent', 'path': tmpfile['path']},
                )

        return tmp['json']


    def remove_system_licence(self, **kwargs):
        self.query_nexus_restapi('system/license',
           method='DELETE', status_code=[200, 204], **kwargs
        )


    def get_nexus_blobstores(self, store_type=None,
        return_as_map=False, **kwargs
    ):
        def format_return(res):
            if not return_as_map:
                return res

            resmap = {}

            for x in res:
                resmap[x['name']] = x

            return resmap

        tmp = self.query_nexus_restapi('blobstores',
          **kwargs
        )

        if not store_type:
            return format_return(tmp['json'])

        new_res = []

        for x in tmp['json']:
            if store_type.lower() == x['type'].lower():
                new_res.append(x)

        return format_return(new_res)


    def get_nexus_blobstore_groups(self, by_member_access=None,
        return_as_map=False, **kwargs
    ):
        res = self.get_nexus_blobstores('group',
          return_as_map=return_as_map, **kwargs
        )

        if not res:
            return res

        if not by_member_access:
            return res

        cmap = {}
        griter = res

        if return_as_map:
            griter = res.values()

        for x in griter:
            x.update(self.read_nexus_blobstore_group_config(x))

            for m in x['members']:
                cmap[m] = x

        return {
          'groups': res,
          'by_member': cmap,
        }


    def get_nexus_blobstore_parent_group(self, store_name, **kwargs):
        tmp = self.get_nexus_blobstore_groups(**kwargs)

        if not tmp:
            return tmp

        for x in tmp:
            x.update(self.read_nexus_blobstore_group_config(x))

            if store_name in x['members']:
                return x

        return None


    def create_nexus_blobstore_file(self, store_cfg, **kwargs):
        self.query_nexus_restapi('blobstores/file',
           body=store_cfg, status_code=[200, 204], **kwargs
        )


    def update_nexus_blobstore_file(self, store_cfg, **kwargs):
        self.query_nexus_restapi('blobstores/file/{}'.format(
             store_cfg['name']
           ), method='PUT', status_code=[200, 204], body=store_cfg,
            **kwargs
        )


    def read_nexus_blobstore_config_file(self, store_cfg, **kwargs):
        tmp = self.query_nexus_restapi('blobstores/file/{}'.format(
             store_cfg['name']
           ), **kwargs
        )

        tmp = tmp['json']
        tmp['name'] = store_cfg['name']
        return tmp


    def create_nexus_blobstore_s3(self, store_cfg, **kwargs):
        self.query_nexus_restapi('blobstores/s3',
           body=store_cfg, status_code=[200, 201, 204], **kwargs
        )


    def update_nexus_blobstore_s3(self, store_cfg, **kwargs):
        self.query_nexus_restapi('blobstores/s3/{}'.format(
             store_cfg['name']
           ), method='PUT', body=store_cfg,
           status_code=[200, 204], **kwargs
        )


    def read_nexus_blobstore_config_s3(self, store_cfg, **kwargs):
        tmp = self.query_nexus_restapi('blobstores/s3/{}'.format(
             store_cfg['name']
           ), **kwargs
        )

        tmp = tmp['json']
        tmp['name'] = store_cfg['name']
        return tmp


    def _get_blobstore_type_fn(self, store_type):
        st = store_type.lower()

        if not self._blobstore_func_map:
            self._blobstore_func_map = {
                'file': {
                  'read': self.read_nexus_blobstore_config_file,
                  'create': self.create_nexus_blobstore_file,
                  'update': self.update_nexus_blobstore_file,
                },
                's3': {
                  'read': self.read_nexus_blobstore_config_s3,
                  'create': self.create_nexus_blobstore_s3,
                  'update': self.update_nexus_blobstore_s3,
                },
                'group': {
                  'read': self.read_nexus_blobstore_group_config,
                  ##'create': self.create_nexus_blobstore_s3,
                  'update': self.update_nexus_blobstore_group_config,
                },
            }

        res = self._blobstore_func_map.get(st, None)

        ansible_assert(res,\
           "Unsupported blobstore type '{}': must be one"\
           " of these: {}".format(st, list(self._blobstore_func_map.keys()))
        )

        return res


    def create_nexus_blobstore(self, store_type, store_cfg, **kwargs):
        fn = self._get_blobstore_type_fn(store_type)
        fn = fn['create']
        fn(store_cfg, **kwargs)


    def update_nexus_blobstore(self, store_type, store_cfg, **kwargs):
        fn = self._get_blobstore_type_fn(store_type)
        fn = fn['update']
        fn(store_cfg, **kwargs)


    def read_nexus_blobstore_config(self, store_type, store_cfg, **kwargs):
        fn = self._get_blobstore_type_fn(store_type)
        fn = fn['read']
        return fn(store_cfg, **kwargs)


    def remove_nexus_blobstore(self, store_name, **kwargs):
        self.query_nexus_restapi('blobstores/{}'.format(store_name),
           method='DELETE', status_code=[200, 204], **kwargs
        )


    def convert_nexus_blobstore_to_group(self, store_name, new_store_name,
        **kwargs
    ):
        self.query_nexus_restapi('blobstores/group/convert/{}/{}'.format(
             store_name, new_store_name
           ), method='POST', **kwargs
        )


    def read_nexus_blobstore_group_config(self, store_cfg, **kwargs):
        tmp = self.query_nexus_restapi('blobstores/group/{}'.format(
             store_cfg['name']
           ), **kwargs
        )

        tmp = tmp['json']
        tmp['name'] = store_cfg['name']
        return tmp


    def update_nexus_blobstore_group_config(self, store_cfg, **kwargs):
        self.query_nexus_restapi('blobstores/group/{}'.format(
             store_cfg['name'],
           ), method='PUT', body=store_cfg,
           status_code=[200, 204], **kwargs
        )


    def get_nexus_repositories(self, details=False, repo_format=None,
        repo_type=None, return_as_map=False, **kwargs
    ):
        def format_return(res):
            if not return_as_map:
                return res

            resmap = {}

            for x in res:
                resmap[x['name']] = x

            return resmap

        qp = 'repositories'

        if details:
            qp = 'repositorySettings'

        tmp = self.query_nexus_restapi(qp,
          **kwargs
        )

        if not repo_format and not repo_type:
            return format_return(tmp['json'])

        new_res = []

        for x in tmp['json']:
            if repo_format and repo_format.lower() != x['format'].lower():
                ## optionally filter out by format
                continue

            if repo_type and repo_type.lower() != x['type'].lower():
                ## optionally filter out by type
                continue

            new_res.append(x)

        return format_return(new_res)


    def get_nexus_repo_details(self, repo_cfg, **kwargs):
        tmp = self.query_nexus_restapi('repositories/{}/'.format(
             repo_cfg['name']
           ), **kwargs
        )

        tmp = tmp['json']
        return tmp


    def read_nexus_repo_config(self, repo_format, repo_type,
        repo_cfg, **kwargs
    ):
        tmp = self.query_nexus_restapi('repositories/{}/{}/{}'.format(
             repo_format, repo_type, repo_cfg['name']
           ), **kwargs
        )

        tmp = tmp['json']
        return tmp


    def create_nexus_repo_base(self, path, repo_cfg, **kwargs):
        ## optionally apply senseable defaults for mandatory
        ## repo settings (any kind)
        repo_cfg.setdefault('online', True)

        self.query_nexus_restapi(path,
           body=repo_cfg, status_code=[200, 201], **kwargs
        )


    def create_nexus_hosted_repo(self, path, repo_cfg, **kwargs):
        ## optionally apply senseable defaults for mandatory
        ## hosted repo settings
        st_cfg = repo_cfg.setdefault('storage', None) or {}
        st_cfg.setdefault('blobStoreName', 'default')
        st_cfg.setdefault('writePolicy', 'ALLOW_ONCE')
        st_cfg.setdefault('strictContentTypeValidation', True)

        repo_cfg['storage'] = st_cfg
        self.create_nexus_repo_base(path, repo_cfg, **kwargs)


    def create_nexus_repo_docker_hosted(self, repo_cfg, **kwargs):
        d_cfg = repo_cfg.setdefault('docker', None) or {}
        d_cfg.setdefault('v1Enabled', False)
        d_cfg.setdefault('forceBasicAuth', False)

        repo_cfg['docker'] = d_cfg

        self.create_nexus_hosted_repo(
          'repositories/docker/hosted', repo_cfg, **kwargs
        )


    def update_nexus_repo_docker_hosted(self, repo_cfg, **kwargs):
        self.query_nexus_restapi('repositories/docker/hosted/{}'.format(
             repo_cfg['name']
           ), method='PUT', body=repo_cfg,
           status_code=[200, 204], **kwargs
        )


    def _get_repo_specific_fn(self, repo_format, repo_type):
        rf = repo_format.lower()
        rt = repo_type.lower()

        if not self._repo_func_map:
            self._repo_func_map = {
              'hosted': {
                'docker': {
                  'create': self.create_nexus_repo_docker_hosted,
                  'update': self.update_nexus_repo_docker_hosted,
                },
              },
            }

        tmp = self._repo_func_map.get(rt, None)

        ansible_assert(tmp,\
           "Unsupported repository type '{}': must be one"\
           " of these: {}".format(rt, list(self._repo_func_map.keys()))
        )

        res = tmp.get(rf, None)

        ansible_assert(res,\
           "Unsupported repository format '{}': must be one"\
           " of these: {}".format(rf, list(tmp.keys()))
        )

        return res


    def create_nexus_repository(self, repo_format, repo_type,
        repo_cfg, **kwargs
    ):
        fn = self._get_repo_specific_fn(repo_format, repo_type)
        fn = fn['create']
        fn(repo_cfg, **kwargs)


    def update_nexus_repository(self, repo_format, repo_type,
        repo_cfg, **kwargs
    ):
        fn = self._get_repo_specific_fn(repo_format, repo_type)
        fn = fn['update']
        fn(repo_cfg, **kwargs)


    def remove_nexus_repository(self, repo_name, **kwargs):
        self.query_nexus_restapi('repositories/{}'.format(repo_name),
           method='DELETE', status_code=[200, 204], **kwargs
        )


    def get_nexus_cleanup_policies(self, policy_format=None,
        return_as_map=False, **kwargs
    ):
        def format_return(res):
            if not return_as_map:
                return res

            resmap = {}

            for x in res:
                resmap[x['name']] = x

            return resmap

        tmp = self.query_nexus_restapi('cleanup-policies', **kwargs)

        if not policy_format:
            return format_return(tmp['json'])

        new_res = []

        for x in tmp['json']:
            if policy_format != x['format']:
                ## optionally filter out by format
                continue

            new_res.append(x)

        return format_return(new_res)


    def read_nexus_cleanup_policy_config(self, pol_cfg, **kwargs):
        tmp = self.query_nexus_restapi('cleanup-policies/{}'.format(
             pol_cfg['name']
           ), **kwargs
        )

        return tmp['json']


    def create_nexus_cleanup_policy(self, pol_cfg, **kwargs):
        tmp = self.query_nexus_restapi('cleanup-policies',
          body=pol_cfg, status_code=[200, 201], **kwargs
        )

        return tmp['json']


    def update_nexus_cleanup_policy(self, pol_cfg, **kwargs):
        self.query_nexus_restapi('cleanup-policies/{}'.format(
             pol_cfg['name']
           ), method='PUT', body=pol_cfg,
           status_code=[200, 204], **kwargs
        )


    def remove_nexus_cleanup_policy(self, pol_name, **kwargs):
        self.query_nexus_restapi('cleanup-policies/{}'.format(pol_name),
           method='DELETE', status_code=[200, 204], **kwargs
        )


    def create_nexus_task(self, task_cfg, **kwargs):
        task_cfg.setdefault('enabled', True)
        task_cfg.setdefault('notificationCondition', 'FAILURE')

        tmp = self.query_nexus_restapi('tasks',
          body=task_cfg, status_code=[200, 201], **kwargs
        )

        return tmp['json']


    def run_nexus_task(self, tinfo, **kwargs):
        self.query_nexus_restapi('tasks/{}/run'.format(
             tinfo['id'],
          ), method='POST', status_code=[200, 204], **kwargs
        )


    def remove_nexus_task(self, task_id, **kwargs):
        self.query_nexus_restapi('tasks/{}'.format(
            task_id,
          ), method='DELETE', status_code=[200, 204], **kwargs
        )


    #### create a task and immediatelly run it once, and on
    #### default remove directly again
    def run_nexus_adhoc_task(self, task_cfg, keep=False, **kwargs):
        task_cfg.setdefault('frequency', {'schedule': 'manual'})

        tinfo = self.create_nexus_task(task_cfg, **kwargs)
        self.run_nexus_task(tinfo)

        if not keep:
            self.remove_nexus_task(tinfo['id'], **kwargs)


    def get_user_sources(self, **kwargs):
        tmp = self.query_nexus_restapi('security/user-sources', **kwargs)

        res = {}
        for us in tmp['json']:
            res[us['id']] = us

        return res


    def get_available_realms(self, as_map=True, **kwargs):
        tmp = self.query_nexus_restapi('security/realms/available', **kwargs)

        if not as_map:
            return tmp['json']

        ## convert list of "objects" to mapping
        res = {}

        for x in tmp['json']:
            res[x] = x

        return res


    def get_active_realms(self, **kwargs):
        tmp = self.query_nexus_restapi('security/realms/active', **kwargs)
        return tmp['json']


    def set_active_realms(self, realm_lst, **kwargs):
        self.query_nexus_restapi('security/realms/active',
           body=realm_lst, method='PUT', status_code=[200, 204],
           **kwargs
        )


    # expects a list of realms which are expected to be
    # active, take care that this is the case
    def ensure_realms_are_active(self, realms, exclusive=False,
      force=False, diff=True, **kwargs
    ):
        def_nx_realm = self.special_nexus_realms['default_nexus_auth']
        cur_active_lst = self.get_active_realms(**kwargs)

        new_lst = []

        if isinstance(realms, string_types):
            realms = [realms]

        if exclusive:
            ## in exclusive mode only realms explicitly given
            ## as input should be active
            for x in realms:
                if not isinstance(x, string_types):
                    ## if element is not a simple string assume a tuple
                    ## (pos, realm-name), but in exclusive mode pos should
                    ## not matter because only input realms counts and
                    ## they should already in correct order
                    _, rname = x
                    x = rname

                new_lst.append(x)

        else:
            res = {}

            i = 0
            for x in cur_active_lst:
                res[x] = i
                i += 1

            new_lst = copy.deepcopy(cur_active_lst)

            for x in realms:
                pos = None
                rname = x

                if not isinstance(x, string_types):
                    pos, rname = x

                op = res.get(rname, None)

                if op is not None and (pos is None or op == pos):
                    ## realm is active already and at the right pos => noop
                    continue

                if op is not None:
                    ## ensure already active realm is removed from
                    ## old position
                    ##
                    ## note: important to remove here by value, not
                    ##   position, because as we manipulate new list
                    ##   "live" here after the 1st changes old positions
                    ##   will be wrong
                    new_lst.remove(rname)

                if pos is None:
                    new_lst.append(rname)
                else:
                    new_lst.insert(pos, rname)

        update_active_realms = True
        diff_map = {}

        if diff:
            ## check if current list and newly build list differ at all
            cmap_old = {}

            diff_moved = {}
            diff_added = {}
            diff_removed = {}

            i = 0
            for x in cur_active_lst:
                cmap_old[x] = i
                i += 1
            
            i = -1
            for x in new_lst:
                i += 1

                old_pos = cmap_old.pop(x, None)

                if old_pos is None:
                    ## current realm is new
                    diff_added[x] = i
                    continue

                if old_pos == i:
                    ## nothing changed
                    continue

                ## position of realm updated
                diff_moved[x] = {
                  'from': old_pos, 'to': i,
                }

            for k, v in cmap_old.items():
                diff_removed[k] = v

            if diff_moved or diff_added or diff_removed:
                 diff_map = {
                   'moved': diff_moved,
                   'added': diff_added,
                   'removed': diff_removed,
                 }

            else:
                ## no diff, no update needed
                update_active_realms = False

        if not update_active_realms:
            return None

        ansible_assert(force or def_nx_realm in new_lst,
             "Caller requested to set an active realm list without the"\
           + " default nexus auth realm '{}'. Please make sure this is"\
           + " really what you want to do, if so set force flag to"\
           + " true.".format(def_nx_realm)
        )

        self.set_active_realms(new_lst, **kwargs)

        if not diff:
            return new_lst

        return (new_lst, diff_map)


    def ensure_realms_are_deactive(self, realms, 
      force=False, diff=True, **kwargs
    ):
        def_nx_realm = self.special_nexus_realms['default_nexus_auth']
        cur_active_lst = self.get_active_realms(**kwargs)

        new_lst = []

        if isinstance(realms, string_types):
            realms = [realms]

        ansible_assert(force or def_nx_realm not in realms,
             "Caller requested to deactivate default nexus auth realm"\
           + " '{}'. Please make sure this is really what you want to do,"\
           + " if so set force flag to true.".format(def_nx_realm)
        )

        diff_map = {}

        i = 0
        for x in cur_active_lst:
            if x in realms:
                diff_map[x] = i
            else:
                ## keep every already active realm which is not
                ## explicitly excluded by given method param
                new_lst.append(x)

            i += 1

        if not diff_map:
            return None

        self.set_active_realms(new_lst, **kwargs)

        if not diff:
            return new_lst

        diff_map = {'removed': diff_map}
        return (new_lst, diff_map)


    def map_user_source_to_realm_name(self, usrc, optional=False, **kwargs):
        all_sources = self.get_user_sources(**kwargs)
        usmap = all_sources.get(usrc, None)

        if not usmap and optional:
            return None

        ansible_assert(usmap,
            "Given nexus user source '{}' does not exist on server. Must"
            " be one of these:\n{}".format(
               usrc, json.dumps(all_sources, indent=2)
            )
        )

        return usmap['name']


    def check_user_source_valid(self, usrc, **kwargs):
        rname = self.map_user_source_to_realm_name(usrc, **kwargs)
        ac_realms = self.get_active_realms(**kwargs)

        ansible_assert(rname in ac_realms,
            "Given user source '{}' with corresponding realm name"\
            " '{}' is not one of the currently active realms on"\
            " the server:\n{}".format(usrc, rname, ac_realms)
        )


    def postfix_user_res(self, users, single=False):
        if not isinstance(users, list):
            users = [users]

        res = {}
        for u in users:
            res[u['userId']] = u

            for k, v in self.nexus_key_mappings_users.items():
                u[v] = u.pop(k)

        if single and len(res) == 1:
            res = res[next(iter(res))]

        return res


    def postfix_role_res(self, roles, single=False):
        if not isinstance(roles, list):
            roles = [roles]

        res = {}
        for r in roles:
            res[r['id']] = r

        if single and len(res) == 1:
            res = res[next(iter(res))]

        return res


    def get_nexus_users(self, user_id=None, realm=None, **kwargs):
        q = {}

        if user_id:
            q['userId'] = user_id

        if realm:
            q['source'] = realm

        tmp = self.query_nexus_restapi('security/users',
            url_query=q, **kwargs
        )

        return self.postfix_user_res(tmp['json'])


    def check_nexus_user_valid(self, user_id, **kwargs):
        realm = kwargs.get('realm', None)
        usr = self.get_nexus_users(user_id=user_id, **kwargs)

        msg_extra = ''

        if realm:
            msg_extra = " for realm '{}'".format(realm)

        ansible_assert(usr,
            "No user with id '{}' seems to exist on nexus"\
            " server".format(user_id) + msg_extra
        )


    def create_nexus_builtin_user(self, user_map, **kwargs):
        for k, v in self.nexus_key_mappings_users.items():
            user_map[k] = user_map.pop(v)

        tmp = self.query_nexus_restapi('security/users',
            body=user_map, **kwargs
        )

        return self.postfix_user_res(tmp['json'], single=True)


    def remove_nexus_user(self, usr_id, realm, **kwargs):
        ##
        ## note: nexus basically has two kinds of "realm ids" which
        ##   are slightly different but mappable to one another for
        ##   what ever reason, for most user related commandos we need
        ##   the so called "user source id", but for the user delete
        ##   command which one might call "realm id", externally we
        ##   will support both of these and map here internally when
        ##   necessary
        ##
        mapped_realm = self.map_user_source_to_realm_name(
           realm, optional=True, **kwargs
        )

        if not mapped_realm:
            ##
            ## assume given realm is realm-id, check if this
            ## is actually the case
            ##
            realms = self.get_available_realms(**kwargs)

            ansible_assert(mapped_realm in realms,
                "Given nexus realm parameter value '{}' is neither a"\
                " valid user source id nor is it a valid realm id."\
                " Realm ID's avaible on server:\n{}".format(
                   realm, json.dumps(realms, indent=2)
                )
            )

            mapped_realm = realm

        q = {'realm': mapped_realm}

        self.query_nexus_restapi('security/users/{}'.format(usr_id),
           method='DELETE', url_query=q, status_code=[200, 204], **kwargs
        )


    def update_nexus_user(self, user_map, realm, **kwargs):
        for k, v in self.nexus_key_mappings_users.items():
            user_map[k] = user_map.pop(v)

        self.query_nexus_restapi(
           'security/users/{}'.format(user_map['userId']),
           body=user_map, method='PUT', status_code=[200, 204], **kwargs
        )


    def update_nexus_user_password(self, user_id, new_pw, realm, **kwargs):
        ansible_assert(realm == 'default',
           "changing user passwords is only supported for nexus"\
           " builtin (default) realm, not for realm '{}'".format(realm)
        )

        self.query_nexus_restapi(
           'security/users/{}/change-password'.format(user_id), body=new_pw,
           method='PUT', headers={'Content-Type': 'text/plain'},
           status_code=[200, 204], **kwargs
        )


    def test_nexus_user_login(self, user_id, password,
        raise_error=True, **kwargs
    ):
        ##
        ## simply try a path which hopefully any kind of users with
        ## any kind of privileges / roles defined is allowed to
        ## access and check if server returns an auth error or not
        ##
        ## note: even when anonymous access is allowed which technically
        ##   means we are able to access this resource without any kind
        ##   of authentication, even then when you give credentials
        ##   server will validate them which is good for us in this case here
        ##
        res = self.query_nexus_restapi('formats/upload-specs',
           url_username=user_id, url_password=password,
           status_code=[200, 401], **kwargs
        )

        st = res['status']

        if st in [200]:
            return True

        if not raise_error:
            return False

        raise AnsibleError(
            "nexus login test for user '{}' failed".format(user_id)
        )


    def get_nexus_eula(self, **kwargs):
        tmp = self.query_nexus_restapi('system/eula', **kwargs)
        return tmp['json']


    def set_nexus_eula(self, settings, **kwargs):
        tmp = self.query_nexus_restapi('system/eula',
            body=settings, status_code=[200, 204], **kwargs
        )


    def get_nexus_anonymous_access_settings(self, **kwargs):
        tmp = self.query_nexus_restapi('security/anonymous', **kwargs)
        return tmp['json']


    def set_nexus_anonymous_access_settings(self, settings, **kwargs):
        tmp = self.query_nexus_restapi('security/anonymous',
            method='PUT', body=settings, **kwargs
        )

        return tmp['json']


    def get_nexus_roles(self, source=None, **kwargs):
        path_opts = {}

        if source:
            path_opts['source'] = source

        tmp = self.query_nexus_restapi('security/roles',
            url_query=path_opts, **kwargs
        )

        return self.postfix_role_res(tmp['json'])


    def create_nexus_role(self, role_cfg, source=None, **kwargs):
        tmp = self.query_nexus_restapi('security/roles',
            body=role_cfg, **kwargs
        )

        return self.postfix_role_res(tmp['json'], single=True)


    def update_nexus_role(self, role_cfg, source=None, **kwargs):
        self.query_nexus_restapi(
            'security/roles/{}'.format(role_cfg['id']), body=role_cfg,
            method='PUT', status_code=[200, 204], **kwargs
        )


    def remove_nexus_role(self, role_id, source=None, **kwargs):
        self.query_nexus_restapi('security/roles/{}'.format(role_id),
           method='DELETE', status_code=[200, 204], **kwargs
        )

