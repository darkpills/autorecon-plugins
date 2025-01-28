from autorecon.plugins import ServiceScan
from shutil import which
import os

class Hexhttp(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "HexHTTP"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 2

    def check(self):
        if os.path.isfile('/opt/my-resources/HExHTTP/hexhttp.py') is None:
            self.error('The program hexhttp could not be found. Make sure it is installed.')
            return False

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("python3 /opt/my-resources/HExHTTP/hexhttp.py -u {http_scheme}://{address}:{port}/ -o {scandir}/"+outfile) 

