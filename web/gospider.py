from autorecon.plugins import ServiceScan

class Gospider(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Gospider"
        self.tags = ['default', 'safe', 'http', 'darkpills']
        self.priority = 2

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            outfileUrl = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_url.txt'
            outfileParam = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'_param.txt'
            await service.execute("gospider -s '{http_scheme}://{address}:{port}/' -c 10 -d 5 --blacklist '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)' --other-source", outfile=outfile) 
            await service.execute('cat {scandir}/'+outfile+' | grep -e "code-200" | sed -e s#"^.* - \(http.*\)$"#"\\1"#g"', outfile=outfileUrl) 
            await service.execute("cat {scandir}/"+outfileUrl+" |grep '=' | qsreplace -a", outfile=outfileParam) 