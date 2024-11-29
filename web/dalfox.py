from autorecon.plugins import ServiceScan

class Dalfox(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Dalfox"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 3

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            paramsOut = '{protocol}_{port}_{http_scheme}_params.txt'
            await service.execute("cat {scandir}/*_param.txt | grep {address} | sort -u", outfile=paramsOut) 
            await service.execute(f"dalfox file {paramsOut}", outfile=outfile)