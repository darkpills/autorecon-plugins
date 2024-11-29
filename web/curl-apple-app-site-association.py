from autorecon.plugins import ServiceScan

class CurlAppleAppSiteAssociation(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "CurlAppleAppSiteAssociation"
        self.tags = ['default', 'safe', 'http', 'darkpills']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)
        self.add_pattern('^HTTP.*200.*')

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("curl -s -k -i -L -H 'Accept-Language: en-US,en;q=0.5' -H'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0' {http_scheme}://{address}:{port}/apple-app-site-association", outfile=outfile)