from autorecon.plugins import ServiceScan

class Wafw00f(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Wafw00f"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = -1

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)
        self.add_pattern('behind.*$', 'WAF found (consider reducing max parallel plugins to 1: -m 1): {match}')

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("wafw00f -a '{http_scheme}://{address}:{port}/'", outfile=outfile)