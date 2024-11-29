from autorecon.plugins import ServiceScan
from shutil import which

class Arjun(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Arjun"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 2

    def check(self):
        if which('nuclei') is None:
            self.error('The program nuclei could not be found. Make sure it is installed.')
            return False

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            outfileParam = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_param.txt'
            await service.execute("arjun -u {http_scheme}://{address}:{port}/ -oT {scandir}/"+outfileParam, outfile=outfile) 