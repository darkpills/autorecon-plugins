from autorecon.plugins import ServiceScan
import os

class CloakQuest3r(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "CloakQuest3r"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 2

    def check(self):
        if os.path.isfile('/opt/my-resources/CloakQuest3r//cloakquest3r.py') is None:
            self.error('The program cloakquest3r could not be found. Make sure it is installed.')
            return False
        
    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("cd /opt/my-resources/CloakQuest3r/; echo \"yes\\nno\" | python3 cloakquest3r.py {http_scheme}://{address}:{port}/", outfile=outfile)