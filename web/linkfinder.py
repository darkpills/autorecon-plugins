from autorecon.plugins import ServiceScan

class LinkFinder(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "LinkFinder"
        self.tags = ['default', 'safe', 'http', 'darkpills']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("/opt/tools/LinkFinder/venv/bin/python3 /opt/tools/LinkFinder/linkfinder.py -d -o cli -i {http_scheme}://{address}:{port}/", outfile=outfile)