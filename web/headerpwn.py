from autorecon.plugins import ServiceScan

class HeaderPwn(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "HeaderPwn"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.patterns = []
        self.priority = 5

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            # https://raw.githubusercontent.com/devanshbatham/headerpwn/main/headers.txt
            await service.execute("headerpwn  -headers /opt/my-resources/SecLists/headers.txt -url {http_scheme}://{address}:{port}/", outfile=outfile) 