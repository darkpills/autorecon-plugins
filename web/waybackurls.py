from autorecon.plugins import ServiceScan

class Waybackurls(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Waybackurls"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 2

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_url.txt'
            # it finds nothing if we add the port
            await service.execute("waybackurls {http_scheme}://{address}/ 2>&1", outfile=outfile)