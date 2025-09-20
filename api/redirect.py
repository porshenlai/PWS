import aiohttp
import aio_request
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

		async with aiohttp.ClientSession() as client_session:
			client = aio_request.setup(
				transport=aio_request.AioHttpTransport(client_session),
				endpoint="https://www.cyberpiers.com/",
			)
			response_ctx = client.request(
				aio_request.get("/index.html"),
				deadline=aio_request.Deadline.from_timeout(5)
			)
			async with response_ctx as response:
				print((await response.read()).decode('utf8'))

		return rio.JSON({"R":"OK","A":arg,"C":self.COUNT})
PHMClass=H

