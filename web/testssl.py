from autorecon.plugins import ServiceScan

class Testssl(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Testssl"
		self.tags = ['default', 'safe', 'ssl', 'tls', 'darkpills']
		self.patterns = []
		self.add_pattern('vulnerable$')
		self.add_pattern('not offered$')
		self.priority = 3

	def configure(self):
		self.match_all_service_names(True)
		self.require_ssl(True)

	async def run(self, service):
		if service.protocol == 'tcp' and service.secure:
			outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
			await service.execute('/opt/tools/testssl.sh/testssl.sh {address}:{port} 2>&1 || echo "ok"', outfile=outfile)


