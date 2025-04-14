
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import collections
import json

from ansible.errors import \
  AnsibleAssertionError,\
  AnsibleOptionsError,\
  AnsibleError

####from ansible.module_utils._text import to_native
from ansible.module_utils.six import iteritems, string_types

from ansible_collections.smabot.base.plugins.module_utils.plugins.action_base import BaseAction
from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert
from ansible.utils.display import Display


display = Display()


class NexusBase(BaseAction):

    def __init__(self, *args, **kwargs):
        super(NexusBase, self).__init__(*args, **kwargs)
        self._api_pw_override = None


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
    def nexus_url_restapi(self):
        return "{}/{}".format(self.nexus_url, self.rest_api_basepath)

    @property
    def nexus_auth_user(self):
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
        url_query=None, body=None, fwargs=None, **kwargs
    ):
        ansible_assert(resource,
           "bad nexus_api query call, must provide an"\
           " non-empty resource path"
        )

        modargs = fwargs or {}

        if body:
            method = method or 'POST'
            modargs['body'] = body

            if isinstance(body, (list, collections.abc.Mapping)):
                modargs.setdefault('body_format', 'json')

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
                raise AnsibleOptionsError(
                   "Nexus api rest call to '{}' needs authorisation,"\
                   " caller must either provide a password or a"\
                   " token".format(modargs['url'])
                )

        return self.exec_module('ansible.builtin.uri',
            modargs=modargs, **kwargs
        )


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
            res[x['id']] = x

        return res


    def get_active_realms(self, **kwargs):
        tmp = self.query_nexus_restapi('security/realms/active', **kwargs)
        return tmp['json']


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

        if len(res) == 1:
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


    def get_nexus_anonymous_access_settings(self, **kwargs):
        tmp = self.query_nexus_restapi('security/anonymous', **kwargs)
        return tmp['json']


    def set_nexus_anonymous_access_settings(self, settings, **kwargs):
        tmp = self.query_nexus_restapi('security/anonymous',
            method='PUT', body=settings, **kwargs
        )

        return tmp['json']

