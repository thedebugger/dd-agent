import re
import requests
import urlparse

# project
from util import headers
from checks import AgentCheck

# 3rd party
import simplejson as json

class Hydra(AgentCheck):
    """ 
    """
    def check(self, instance):
        if 'hydra_status_url' not in instance:
            raise Exception('Hydra instance missing "hydra_status_url" value.')

        base_url = instance.get('hydra_status_url')

        #Getting Number of projects
        tags = instance.get('tags', []) 
        response, content_type = self._get_data(instance)
        self.gauge('hydra.numberOfProjects', len(response))

        # Getting the size of the queue
        queue_instance = instance
        queue_instance['hydra_status_url'] = base_url + '/queue'
        response, content_type = self._get_data(queue_instance)
        self.gauge('hydra.queue', len(response))

        # Getting number of slaves
        slaves_instance = instance
        slaves_instance['hydra_status_url'] = base_url + "/machines"
        response, content_type = self._get_data(instance)
        total_number_of_builders = 0 
        for line in response.splitlines():
            builder = re.match(re.compile(r".*(hydra-builder[0-9]+)"), line)
            try:
                self.log.info("Builder:%s" %builder.groups())
                total_number_of_builders += 1
            except:
                pass

        self.gauge('hydra.total_builders', total_number_of_builders)
        instance['hydra_status_url'] = base_url

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
