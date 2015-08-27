from util import headers
from checks import AgentCheck

import simplejson as json

class Gerrit(AgentCheck):
    def check(self, instance):
        if 'gerrit_status_url' not in instance:
            raise Exception('Hydra instance missing "gerrit_status_url" value.')
        base_url = instance.get('hydra_status_url')

        projects_instance = instance
        projects_instance['gerrit_status_url'] = base_url + "/projects/"

    def _get_data(self, instance):
        url = instance.get('hydra_status_url')

        auth = None
        if 'user' in instance and 'password' in instance:
            auth = (instance['user'], instance['password'])

        # Submit a service check for status page availability.
        parsed_url = urlparse.urlparse(url)
        hydra_host = parsed_url.hostname
        hydra_port = parsed_url.port or 80
        service_check_name = 'hydra.can_connect'
        service_check_tags = ['host:%s' % hydra_host, 'port:%s' % hydra_port]
        try:
            headers = {'Accept': 'application/json'}
            r = requests.get(url, auth=auth, headers=headers)
            r.raise_for_status()
        except Exception:
            self.service_check(service_check_name, AgentCheck.CRITICAL,
                               tags=service_check_tags)
            raise
        else:
            self.service_check(service_check_name, AgentCheck.OK,
                               tags=service_check_tags)

        body = r.content
        resp_headers = r.headers
        return body, resp_headers.get('content-type', 'text/plain')
       
