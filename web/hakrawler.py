from autorecon.plugins import ServiceScan

class Hakrawler(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Hakrawler"
        self.tags = ['default', 'safe', 'http', 'darkpills']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_url.txt'
            await service.execute("echo {http_scheme}://{address}:{port}/ | hakrawler -d 3", outfile=outfile) 