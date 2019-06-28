# -*- coding: utf-8 -*-
'''Zerto VirtualizationSite object'''

from zertoobject import ZertoObject
from vm import UnprotectedVM


class VirtualizationSite(ZertoObject):

    def __init__(self, **kwargs):
        self.values = kwargs
        self.name = kwargs['VirtualizationSiteName']
        self.identifier = kwargs['SiteIdentifier']
        obj_map = {
                "datastores": Datastore,
                "datastoreclusters": None,
                "folders": Folder,
                "hosts": Host,
                "hostclusters": HostCluster,
                "networks": Network,
                "resourcepools": ResourcePool,
                "vms": UnprotectedVM
              }
        for k, obj in obj_map.items():
            if obj is not None:
                dicts = kwargs.get(k, None)
                if dicts: 
                    instances = [obj(**d) for d in dicts] 
                else:
                    instances = None
                setattr(self, k, instances)
        

    def __str__(self):
        return 'name={0}, identifier={1}'.format(
            self.name, self.identifier)


class Network(ZertoObject):

    def __init__(self, **kwargs):
        self.values = kwargs
        self.name = kwargs['VirtualizationNetworkName']
        self.identifier = kwargs['NetworkIdentifier']

    def __str__(self):
        return 'name={0}, identifier={1}'.format(
            self.name, self.identifier)


class Datastore(ZertoObject):

    def __init__(self, **kwargs):
        self.values = kwargs
        self.name = kwargs['DatastoreName']
        self.identifier = kwargs['DatastoreIdentifier']

    def __str__(self):
        return 'name={0}, identifier={1}'.format(
            self.name, self.identifier)


class Folder(ZertoObject):

    def __init__(self, **kwargs):
        self.values = kwargs
        self.name = kwargs['FolderName']
        self.identifier = kwargs['FolderIdentifier']

    def __str__(self):
        return 'name={0}, identifier={1}'.format(
            self.name, self.identifier)


class Host(ZertoObject):

    def __init__(self, **kwargs):
        self.values = kwargs
        self.name = kwargs['VirtualizationHostName']
        self.identifier = kwargs['HostIdentifier']

    def __str__(self):
        return 'name={0}, identifier={1}'.format(
            self.name, self.identifier)


class HostCluster(ZertoObject):

    def __init__(self, **kwargs):
        self.values = kwargs
        self.name = kwargs['VirtualizationClusterName']
        self.identifier = kwargs['ClusterIdentifier']

    def __str__(self):
        return 'name={0}, identifier={1}'.format(
            self.name, self.identifier)


class ResourcePool(ZertoObject):

    def __init__(self, **kwargs):
        self.values = kwargs
        self.name = kwargs['ResourcepoolName']
        self.identifier = kwargs['ResourcePoolIdentifier']

    def __str__(self):
        return 'name={0}, identifier={1}'.format(
            self.name, self.identifier)

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
