class Response(object):
	def __init__(self, pid, code, stdout, stderr, obj=None):
		super(Response, self).__init__()
		self.pid		= pid
		self.code 		= code
		self.stdout 	= stdout
		self.stderr 	= stderr
		self.object 	= obj

	@property
	def success(self):
		return self._code == 0

