# -*- coding: utf-8 -*-
'''
Module with api interface for zerto
'''
import base64
import json
import requests

from errors import (                        # NOQA
    ZertoError,
    ZertoUnsupportedApi,
    ZertoServiceError,
    ZertoAuthError,
    Zerto4xx,
    ZertoBadRequest,
    ZertoUnauthorized,
    ZertoForbidden,
    ZertoNotFound,
    ZertoMethodNotAllowed,
    ZertoFailure,
)
from constants import (                     # NOQA
    ZertoConstant,
    ZertoConstantDict,
    AuthenticationMethod,
    authentication_method,
    CommitPolicy,
    commit_policy,
    EntityType,
    entity_type,
    EventCategory,
    event_category,
    EventType,
    event_type,
    PairingStatus,
    pairing_status,
    SiteType,
    site_type,
    TaskState,
    task_state,
    VMType,
    vm_type,
    VPGPriority,
    vpg_priority,
    VPGStatus,
    vpg_status,
    VPGSubStatus,
    vpg_sub_status,
    VRAStatus,
    vra_status,
)
from zertoobject import ZertoObject         # NOQA
from alert import Alert                     # NOQA
from localsite import LocalSite             # NOQA
from peersite import PeerSite               # NOQA
from event import Event                     # NOQA
from task import Task                       # NOQA
from vm import VM, UnprotectedVM                           # NOQA
from vpg import VPG                         # NOQA
from vra import VRA                         # NOQA
from zorg import ZORG                       # NOQA
from serviceprofile import ServiceProfile   # NOQA
from virtualization_site import VirtualizationSite # NOQA


class Zerto(object):

    def __init__(self, url):
        self.url = url
        self.session = None
        self.paths = ['v1']

    def get_url(self, path):
        if not self.url:
            raise ValueError('Invalid url')
        base_path = '/'.join(path.strip('/').split('/')[:2])
        if base_path not in self.paths:
            raise ZertoUnsupportedApi(path)
        url = '{0}/{1}'.format(self.url.rstrip('/'), path.lstrip('/'))
        return url

    def _do_request(self, method, path, data=None, headers=None, **kwargs):
        url = self.get_url(path)
        kwargs = dict([(k, v) for k, v in kwargs.iteritems() if v is not None])
        if data is not None:
            kwargs['data'] = data
        if headers is None:
            headers = {}
        if self.session:
            headers = {
                'x-zerto-session': self.session,
                'content-type': 'application/json',
            }
        if headers:
            kwargs['headers'] = headers
        if 'verify' not in kwargs:
            kwargs['verify'] = False

        req = getattr(requests, method.lower())(url, **kwargs)
        txt = req.text
        if req.status_code == 200:
            return req
        try:
            result = req.json()
        except:
            result = {}
        if isinstance(result, dict):
            req.errcode = result.get('errorCode')
            req.errmsg = result.get('errorMessage')
        else:
            req.errcode = None
            req.errmsg = '{0}'.format(result)
        params = kwargs.get('params')
        if 400 <= req.status_code < 500:
            if req.status_code == 400:
                errcls = ZertoBadRequest
            elif req.status_code == 401:
                errcls = ZertoUnauthorized
            elif req.status_code == 403:
                errcls = ZertoForbidden
            elif req.status_code == 404:
                errcls = ZertoNotFound
            elif req.status_code == 405:
                errcls = ZertoMethodNotAllowed
            else:
                errcls = Zerto4xx
            raise errcls(
                req.status_code, req.errcode, req.errmsg,
                method.upper(), path, params, data)
        if 500 <= req.status_code < 600:
            raise ZertoFailure(
                req.status_code, req.errcode, req.errmsg, req.text,
                method.upper(), path, params, data)
        raise ZertoServiceError(
            req.status_code, req.errcode, req.errmsg,
            method.upper(), path, params, data)

    def get_request(self, path, **kwargs):
        return self._do_request('GET', path, **kwargs)

    def post_request(self, path, data=None, **kwargs):
        return self._do_request('POST', path, data=data, **kwargs)

    def put_request(self, path, data=None, **kwargs):
        return self._do_request('PUT', path, data, **kwargs)

    def delete_request(self, path, **kwargs):
        return self._do_request('DELETE', path, **kwargs)

    def get_apis(self):
        headers = {'content-type': 'application/json'}
        req = self.get_request('v1', headers=headers)
        self.paths = list(sorted(['v1'] + [
            i['href'].split('/', 3)[-1].strip('/')
            for i in req.json()
        ]))
        return req.json()

    def get_session(self, user, password, method=None):
        if not self.paths:
            self.get_apis()
        headers = {
            'Authorization': base64.b64encode(
                '{0}:{1}'.format(user, password))
        }
        session = None
        path = 'v1/session/add'
        if method is not None and not isinstance(method, AuthenticationMethod):
            try:
                method = authentication_method[method]
            except KeyError:
                raise ZertoAuthError(
                    'Invalid authentication method {0}'.format(method))
        if method is None or method.code == 0:
            # Default is windows authentication
            try:
                req = self.post_request(path, headers=headers)
                if req.status_code == requests.codes.ok:
                    session = req.headers.get('x-zerto-session')
            except ZertoUnauthorized:
                pass
        if not session and (method is None or method.code == 1):
            # Try or retry AuthenticationMethod 1 (VirtualizationManager)
            headers['content-type'] = 'application/json'
            try:
                req = self.post_request(
                    path,
                    json.dumps({'AuthenticationMethod': 1}),
                    headers=headers,
                )
                if req.status_code == requests.codes.ok:
                    session = req.headers.get('x-zerto-session')
            except ZertoUnauthorized:
                pass
        if not session:
            raise ZertoAuthError('Invalid user name and/or password')
        self.session = session

    def get_localsite(self, status=None):
        if status:
            req = self.get_request('v1/localsite/pairingstatuses')
            return req.json()
        req = self.get_request('v1/localsite')
        return LocalSite(**req.json())

    def get_peersites(self, siteid=None, status=None, **kwargs):
        if status:
            req = self.get_request('v1/peersites/pairingstatuses')
            return req.json()
        elif siteid is not None:
            req = self.get_request('v1/peersites/{0}'.format(siteid))
            return PeerSite(**req.json())
        req = self.get_request('v1/peersites', params=(kwargs or None))
        return list([PeerSite(**res) for res in req.json()])

    def get_alert(self, alert=None):
        if alert is not None:
            req = self.get_request('v1/alerts/{0}'.format(alert))
            return Alert(**req.json())
        req = self.get_request('v1/alerts')
        return list([Alert(**res) for res in req.json()])

    def get_event(self, event=None, **kwargs):
        '''Retrieve specific event or all'''
        if event is not None:
            req = self.get_request('v1/events/{0}'.format(event))
            return Event(**req.json())
        req = self.get_request('v1/events', params=(kwargs or None))
        return list([Event(**res) for res in req.json()])

    def get_event_categories(self):
        req = self.get_request('v1/events/categories')
        return req.json()

    def get_event_entities(self):
        req = self.get_request('v1/events/entities')
        return req.json()

    def get_event_types(self):
        req = self.get_request('v1/events/types')
        return req.json()

    def get_serviceprofiles(self, serviceprofile=None, **kwargs):
        if serviceprofile is not None:
            req = self.get_request(
                'v1/serviceprofiles/{0}'.format(serviceprofile))
            return ServiceProfile(**req.json())
        req = self.get_request(
            'v1/serviceprofiles', params=(kwargs or None))
        return list([ServiceProfile(**res) for res in req.json()])

    def get_task(self, task=None, **kwargs):
        if task is not None:
            req = self.get_request('v1/tasks/{0}'.format(task))
            return Task(**req.json())
        req = self.get_request('v1/tasks', params=(kwargs or None))
        return list([Task(**res) for res in req.json()])

    def get_virtualization_site(self, siteid=None, get_info=False):
        keys = ("datastoreclusters",
                "datastores",
                "folders",
                "hostclusters",
                "hosts",
                "networks",
                "resourcepools",
                "vms")
        if siteid is not None:
            req = self.get_request(
                'v1/virtualizationsites/{0}'.format(siteid))
            kwargs = req.json()
            if get_info:
                for k in keys:
                    path = 'v1/virtualizationsites/{0}/{1}'.format(siteid, k)
                    subreq = self.get_request(path)
                    kwargs[k] = subreq.json()
            return VirtualizationSite(**kwargs)
        req = self.get_request('v1/virtualizationsites')
        kwarglist = [res for res in req.json()]
        if get_info:
            for d in kwarglist:
                ID = d["SiteIdentifier"]
                for k in keys: 
                    path = 'v1/virtualizationsites/{0}/{1}'.format(ID, k)
                    subreq = self.get_request(path)
                    d[k] = [resp for resp in subreq.json()]
        return [VirtualizationSite(**kwargs) for kwargs in kwarglist]

    def get_vm(self, vmid=None, **kwargs):
        '''Retrieve specific vm or all'''
        if vmid is not None:
            req = self.get_request('v1/vms/{0}'.format(vmid))
            return VM(**req.json())
        # Get protected VMs
        prot_vms = self.get_request('v1/vms', params=(kwargs or None))
        return [VM(**vm_resp) for vm_resp in prot_vms.json()]

    def get_unprotected_vm(self, **kwargs):
        """
        Retrieve unprotected VMs
        """

        # Get unprotected VMs
        VMs = []
        for vs in self.get_virtualization_site():
            path = '/v1/virtualizationsites/{}/vms'.format(vs.identifier)
            unprot_vms = self.get_request(path, params=(kwargs or None))
            for vm_resp in unprot_vms.json():
                VMs.append(UnprotectedVM(**vm_resp))
        return VMs

    def get_vpg(self, vpgid=None, **kwargs):
        '''Retrieve specific vpg or all'''
        if vpgid is not None:
            req = self.get_request('v1/vpgs/{0}'.format(vpgid))
            return VPG(**req.json())
        req = self.get_request('v1/vpgs', params=(kwargs or None))
        return list([VPG(**res) for res in req.json()])

    def get_vra(self, vraid=None, **kwargs):
        if vraid is not None:
            req = self.get_request('v1/vras/{0}'.format(vraid))
            return VRA(**req.json())
        req = self.get_request('v1/vras', params=(kwargs or None))
        return list([VRA(**res) for res in req.json()])

    def get_zorg(self, zorgid=None):
        if zorgid is not None:
            req = self.get_request('v1/zorgs/{0}'.format(zorgid))
            return ZORG(**req.json())
        req = self.get_request('v1/zorgs')
        return list([ZORG(**res) for res in req.json()])

    def get_resources_report(self, **kwargs):
        # fromTimeString={fromTimeString}
        # toTimeString={toTimeString}
        # startIndex={startIndex}
        # count={count}
        # filter={filter}
        if 'filter' in kwargs:
            req = self.get_request(
                'v1/ZvmService/ResourcesReport/getSamplesWithFilter',
                params=(kwargs or None),
            )
        else:
            req = self.get_request(
                'v1/ZvmService/ResourcesReport/getSamples',
                params=(kwargs or None),
            )
        return req.json()

    def create_vpg_settings(self, data, **kwargs):
        """
        Create a VPG via a POST request using the vpgSettings API

        Returns
        -------

        resp : dict 
         A dict of response from API containing vpgSettingsIdentifier
        """

        # Make the initial object
        try:
            resp = self.post_request('v1/vpgSettings', json=data, params=(kwargs or None))
        except ZertoFailure as e:
            print(e)
            print(e.message)
            print(e.errmsg)
            print(e.errcode)
            print(e.status_code)
            raise
        except:
            raise
        vpgid = resp.json()
        # Now commit it
        try:
            path = 'v1/vpgSettings/{}/commit'.format(vpgid)
            resp = self.post_request(path, json=data, params=(kwargs or None))
        except ZertoFailure as e:
            print(e)
            print(e.message)
            print(e.errmsg)
            print(e.errcode)
            print(e.status_code)
            raise
        except:
            raise
        return resp



# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
