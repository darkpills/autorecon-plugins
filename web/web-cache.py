from autorecon.plugins import ServiceScan

class WebCache(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "WebCache"
        self.tags = ['default', 'safe', 'http', 'darkpills']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("cd /opt/my-resources/Web-Cache-Vulnerability-Scanner/; Web-Cache-Vulnerability-Scanner -u {http_scheme}://{address}:{port}/", outfile=outfile)