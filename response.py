class Response(object):
	def __init__(self, obj, pid, code, stdout, stderr):
		super(Response, self).__init__()
		self._object 	= obj
		self._pid		= pid
		self._code 		= code
		self._stdout 	= stdout
		self._stderr 	= stderr

	@property
	def pid(self):
		return self._pid

	@property
	def object(self):
		return self._object

	@property
	def code(self):
		return self._code

	@property
	def success(self):
		return self._code == 0

	@property
	def stdout(self):
		return self._stdout

	@property
	def stderr(self):
		return self._stderr
