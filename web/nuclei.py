from autorecon.plugins import ServiceScan
from shutil import which

class Nuclei(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Nuclei"
        self.tags = ['default', 'safe', 'http', 'long', 'darkpills']
        self.priority = 3
    
    def check(self):
        if which('nuclei') is None:
            self.error('The program nuclei could not be found. Make sure it is installed.')
            return False


    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)
        self.add_pattern('\[critical\].*$', 'Critical vulnerability found: {match}')
        self.add_pattern('\[high\].*$', 'High vulnerability found: {match}')
        self.add_pattern('\[medium\].*$', 'Medium vulnerability found: {match}')
        

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            outfileNocolor = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_nocolor.txt'
            await service.execute("nuclei -ut")
            await service.execute("nuclei -u {http_scheme}://{address}:{port}/ -o {scandir}/"+outfileNocolor, outfile=outfile)