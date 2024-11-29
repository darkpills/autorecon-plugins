from autorecon.plugins import ServiceScan

class SQLMap(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "SQLMap"
        self.tags = ['default', 'safe', 'http', 'long', 'darkpills']
        self.priority = 5

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("sqlmap -u {http_scheme}://{address}:{port}/ --crawl=1 2>&1", outfile=outfile) 
