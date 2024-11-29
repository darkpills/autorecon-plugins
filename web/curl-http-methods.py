from autorecon.plugins import ServiceScan

class CurlHttpMethods(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "CurlHttpMethods"
        self.tags = ['default', 'safe', 'http', 'darkpills']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            for method in ["GET", "PUT", "POST", "PATCH", "OPTIONS", "DELETE", "PROPFIND", "TRACE", "CONNECT"]:
                outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'-'+method.lower()+'.txt'
                curlOptions = "-H 'Accept-Language: en-US,en;q=0.5' -H'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'"
                if (method == "PUT" or method == "POST"):
                    curlOptions += " -d 'test=test'"
                await service.execute("curl -X "+method+" -s -k -i -L "+curlOptions+" {http_scheme}://{address}:{port}/", outfile=outfile) 