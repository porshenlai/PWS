from piers.AIO.Web import WebHome

class H (WebHome.PostHandler) :
	def __init__ (self, args) :
		super().__init__(args)
		self.COUNT=0
	async def handle (self, rio) :
		"""
		[Request]  curl --json '{"ABC":123}' http://localhost:40780/sample
		[Response] {"R":"OK","A":{"ABC":123},"C":1}
		"""
		# assert "N" in rio.Session, "Violation"
		# print("path",rio.path)
		# s, dbn=[], rio.path.group(2)
		ct, arg, hdrs=rio.Req
		self.COUNT+=1;
		return rio.JSON({"R":"OK","A":arg,"C":self.COUNT,"V":0.1})
PHMClass=H
