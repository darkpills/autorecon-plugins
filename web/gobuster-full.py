from autorecon.plugins import ServiceScan

class GobusterFull(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "GobusterFull"
        self.tags = ['default', 'safe', 'http', 'long', 'darkpills']
        self.priority = 10

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
            await service.execute("gobuster dir -u {http_scheme}://{address}:{port}/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -a 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0' -x asp,asp~,aspx,aspx~,backup,bak,bkp,cache,cgi,conf,config,csv,db,html,inc,jar,js,json,jsp,jsp~,lock,log,old,php,php~,py,py~,rar,rb,rb~,sql,sql~,sql.gz,sql.tar.gz,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,wsdl,xml,zip", outfile=outfile) 