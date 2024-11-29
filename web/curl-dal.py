from autorecon.plugins import ServiceScan

class CurlDigitalAssetLinks(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "CurlDigitalAssetLinks"
        self.tags = ['default', 'safe', 'http', 'darkpills']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)
        self.add_pattern('^HTTP.*200.*', 'Digital Asset Links found')

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            # https://blog.chromium.org/2021/04/help-users-log-in-across-affiliated.html
            await service.execute("curl -s -k -i -L -H 'Accept-Language: en-US,en;q=0.5' -H'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0' {http_scheme}://{address}:{port}/.well-known/assetlinks.json", outfile=outfile) 