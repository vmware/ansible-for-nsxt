class PolicyEdgeCluster(object):
    @staticmethod
    def get_resource_base_url(site_id, enforcementpoint_id):
        return '/infra/sites/{}/enforcement-point/{}/edge-clusters'.format(
            site_id, enforcementpoint_id)
