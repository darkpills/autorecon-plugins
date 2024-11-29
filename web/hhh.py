from autorecon.plugins import ServiceScan

class HandyHeaderHacker(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "HandyHeaderHacker"
        self.tags = ['default', 'safe', 'http', 'darkpills']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("python2 /opt/my-resources/HandyHeaderHacker/hhh.py -k -t {http_scheme}://{address}:{port}/", outfile=outfile)