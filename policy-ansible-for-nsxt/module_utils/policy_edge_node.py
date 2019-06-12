class PolicyEdgeNode(object):
    @staticmethod
    def get_resource_base_url(site_id, enforcementpoint_id, edge_cluster_id):
        return ('/infra/sites/{}/enforcement-point/{}/edge-clusters' +
                '/{}/edge-nodes'.format(site_id, enforcementpoint_id,
                                        edge_cluster_id))
