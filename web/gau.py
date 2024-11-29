from autorecon.plugins import ServiceScan
from shutil import which

class Gau(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Gau"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 2

    def check(self):
        if which('gau') is None:
            self.error('The program gau could not be found. Make sure it is installed.')
            return False

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_url.txt'
            await service.execute("gau --o {scandir}/"+outfile+" {http_scheme}://{address}:{port}/") 

