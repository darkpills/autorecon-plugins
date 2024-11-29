from autorecon.plugins import ServiceScan

class GobusterQuick(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "GobusterQuick"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 2

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("gobuster dir -u {http_scheme}://{address}:{port}/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -a 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'", outfile=outfile) 