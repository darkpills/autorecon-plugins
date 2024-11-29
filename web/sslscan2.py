from autorecon.plugins import ServiceScan

class SSLScan2(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SSLScan2"
		self.tags = ['default', 'safe', 'ssl', 'tls', 'darkpills']

	def configure(self):
		self.match_all_service_names(True)
		self.require_ssl(True)

	async def run(self, service):
		if service.protocol == 'tcp' and service.secure:
			outfile = '{protocol}_{port}_{http_scheme}_'+self.name.lower()+'.txt'
			await service.execute('sslscan {address}:{port} 2>&1', outfile=outfile)


