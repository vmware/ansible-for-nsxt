class NSXTPolicyTransportZone(object):
    @staticmethod
    def get_resource_base_url(site_id, enforcementpoint_id):
        return '/infra/sites/{}/enforcement-points/{}/transport-zones'.format(
            site_id, enforcementpoint_id)
