from autorecon.plugins import ServiceScan

class ParamSpider(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "ParamSpider"
        self.tags = ['default', 'safe', 'http']
        self.priority = 2

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            outfileUrl = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_url.txt'
            await service.execute("/root/.pyenv/shims/paramspider -d {address}", outfile=outfile)
            await service.execute("mv results/{address}.txt {scandir}/"+outfileUrl, outfile=outfile)