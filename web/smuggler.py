from autorecon.plugins import ServiceScan

class Smuggler(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Smuggler"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 2

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            outfileNocolor = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_nocolor.txt'
            await service.execute("/opt/tools/smuggler/venv/bin/python3 /opt/tools/smuggler/smuggler.py -u {http_scheme}://{address}:{port}/ -l {scandir}/"+outfileNocolor, outfile=outfile) 