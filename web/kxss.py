from autorecon.plugins import ServiceScan

class Kxss(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Kxss"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 3

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            urlsOut = '{protocol}_{port}_{http_scheme}_urls.txt'
            await service.execute("cat {scandir}/*_url.txt {scandir}/*_param.txt | grep {http_scheme}://{address} | sort -u", outfile=urlsOut) 
            await service.execute("echo '{address}' | kxss "+urlsOut, outfile=outfile)