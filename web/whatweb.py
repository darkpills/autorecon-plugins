from autorecon.plugins import ServiceScan

class Whatweb2(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Whatweb2"
        self.tags = ['default', 'safe', 'http', 'darkpills']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("/usr/local/rvm/gems/ruby-3.2.2@whatweb/wrappers/ruby /opt/tools/WhatWeb/whatweb whatweb --color=never --no-errors -a 3 -v {http_scheme}://{address}:{port}/ 2>&1", outfile=outfile)