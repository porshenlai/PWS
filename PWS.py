# apt install python3-aiofiles
# apt install python3-aiohttp

import asyncio
import ssl

from sys import path as libPath, stdin, exit, argv
from os import listdir, makedirs, path as Path
from re import compile as createRE, fullmatch as matchRE, search as searchRE
from json import loads as json_parse, load as json_read, dumps as json_stringify
from signal import signal, SIGINT
from hashlib import sha256
from base64 import b64encode
from time import time
from mimetypes import guess_type
from aiohttp import web,web_request,ClientSession
from aiofiles import open as async_open

ROOT = Path.dirname(__file__)
if ROOT not in libPath : libPath.insert(0,ROOT)
debug = print

def getLoop() :
	try :
		loop = asyncio.get_running_loop()
	except RuntimeError :
		try :
			loop = asyncio.get_event_loop()
		except RuntimeError :
			loop = asyncio.new_event_loop()
			asyncio.set_event_loop(loop)
	return loop

def stringify( obj, codec=None ) :
	def oh(e) :
		if bytes == type(e) :
			return {"type":"B64","data":__encb64__(e).decode('ascii')}
		return {"type":str(type(e))}
	r = json_stringify(obj, default=oh, ensure_ascii=False)
	return r.encode(codec) if codec else r

def sha (v) :
	s = sha256()
	s.update(v.encode('utf8'))
	return b64encode(s.digest()).decode('ascii')

class XI(Exception) :
	def __init__( self, code, msg="") :
		super().__init__( code, msg )

class RIO :
	## {{{
	RE_FilterDirDot = createRE("/\\.+")
	RE_FilterSlashes = createRE("//+")
	RE_MimeTypeJSON = createRE("^(application)/(json)(;.*)?")
	RE_MimeTypeText = createRE("^(text)/(.*)(;.*)?")
	RE_MimeTypeImage = createRE("^(image)/(.*)(;.*)?")
	RE_MimeTypeBytes = createRE("^(application)/(octet-stream)(;.*)?")

	def __init__ (self, req, srv) :
		self.request=req
		self.server=srv
		self.headers=self.server.CORS.copy()
		self.path=RIO.RE_FilterDirDot.sub("/",req.path)
		self.path=RIO.RE_FilterSlashes.sub("/",req.path)
		self.path="/" + ( self.path[1:] if self.path.startswith('/') else self.path )
		self.Req=(None,None,None) ## content-type, body, header
		self.Session={}
		self.server._log_("%s %s %s" % (req.remote,req.method,self.path), 7)

	async def __prepare__ (self) :
		req,opt=self.request, self.server.Options
		if hasattr(req, "content_length") and req.content_length :
			if req.content_length > opt["MAXREQSIZE"] :
				raise XI("OUT_OF_RESOURCE", "Request body too large.")

		ct=req.content_type if hasattr(req, "content_type") else "application/octet-stream"
		if RIO.RE_MimeTypeJSON.match(ct) :
			self.Req=("JSON", await req.json(), req.headers)
		elif RIO.RE_MimeTypeText.match(ct) :
			self.Req=("Text", await req.text(), req.headers)
		else :
			self.Req=(ct, None, req.headers)

	async def read (self) :
		yield await self.request.read()

	async def save (self, path) :
		if not self.ReqBody :
			async with async_open(path, "wb") as fo :
				async for buf in self.read() :
					await fo.write(buf)
		elif "Text" == self.ReqType :
			async with async_open(path, "w", encoding="utf8") as fo :
				await fo.write(self.ReqBody)
		elif "JSON" == self.ReqType :
			async with async_open(path, "w", encoding="utf8") as fo :
				await fo.write(json_stringify(self.ReqBody))

	def addHeader (self, name, value) :
		self.headers[name]=value

	def JSON (self, data) :
		return self.Bytes(json_stringify(data).encode('utf8'), "application/json")

	def Bytes (self, data, ctype="application/json") :
		return web.Response(body=data, headers=self.headers, content_type=ctype)

	def Redirect (self, url) :
		return web.HTTPFound(url)

	async def File (self, path, mtype=None) :
		try :
			async with async_open(path, "rb") as fd :
				ctype, ec=mtype or guess_type(path)
				if ec : ctype+="; charset="+ec
				self.headers["Content-Type"]=ctype

				rs = web.StreamResponse(status=200, reason="OK", headers=self.headers)
				if web_request.BaseRequest == type(self.request) :
					await rs.prepare(self.request)

				while self.server.Playing :
					buf = await fd.read(self.server.Options["BUFSIZE"])
					if not buf : break
					await rs.write(buf)
			return rs
		except Exception as x :
			return web.HTTPNotFound(text="Error")
	## }}}

class PostHandler :
	## {{{
	def __init__ (self, args) :
		self.Args = args
	def __flush__ (self) :
		pass
	def handle (self, rio) :
		return rio
	## }}}

class PHMC :
	## {{{
	def __init__ (self, size) :
		self.DB = {}
		self.List = []
		self.Size = size

	async def create(self, name) :
		G = { "PHMClass":None }
		async with async_open( name+".py", "r", encoding="utf8" ) as fo :
			exec(await fo.read(), G)
		assert G["PHMClass"], "No such module"
		Arg = {"Root":Path.dirname(name)}
		try :
			async with async_open( name+".json", "r" ) as fo :
				Arg.update(json_parse(await fo.read()))
		except : pass
		print("Reload module",name);
		return (G["PHMClass"](Arg),time())

	async def get(self, name, reload=False) :
		c,t = await super().get(name, reload)
		if not reload and t < Path.getmtime(name+".py") :
			c,t = await super().get(name, True)
		if not callable(getattr(c,"__del__",None)) :
			del self.DB[name]
		return c 

	def set (self, name, value) :
		self.DB[name] = value
		self.List = [v for v in self.List if v != name]
		while len(self.List) >= self.Size :
			self.List.pop(0)
		self.List.append(name)
	## }}}

class PWS :
	## {{{
	def __init__ (
		self,
		host = "0.0.0.0:40780",
		home = {
			"GET":"./GET",
			"POST":"./POST"
		},
		pages = { "INDEX":"index.html" },
		options = {},
		cors = {},
		cafiles = None
	) :
		addr = matchRE(r"(.*):(\d+)", host)
		if not addr : raise Exception("Bad Argument: addr(%s)" % host)
		self.Host, self.Port = addr.group(1), int(addr.group(2))

		self.Options = {
			"BUFSIZE":1048576,
			"MAXREQ":32,
			"MAXREQSIZE":8388608,
			"NO_API_CACHE":False,
			"MASTER_KEY":"Cyberpiers.COM"
		}
		if options : self.Options.update(options)

		self.CORS = {
			"Access-Control-Allow-Origin":"*",
			"Access-Control-Allow-Headers":"*"
		}
		if cors : self.CORS.update(cors)

		self.P = None # TCPSite
		self.Playing = None # Future
		self.LogLevel = 0
		self.ReqCounts = 0
		self.SSLCtx = None
		if cafiles :
			self.SSLCtx = ssl.create_default_context( ssl.Purpose.CLIENT_AUTH )
			self.SSLCtx.load_cert_chain( *cafiles ) # crt,key
		self.Home = home
		self.Pages = pages
		self.PHMCache = PHMC(32)
		self.MasterKey = options["MASTER_KEY"]

	async def _authenticate_ (self, rs) :
		if "Piers-Session" in rs.request.headers :
			sk = rs.request.headers["Piers-Session"]
			sk = sk.split(":")
			skey = sha(":".join(sk[0:2]+[self.MasterKey]))
			if sk[3] != sha(":".join(sk[0:2]+[skey,sk[2]])) :
				return rs.JSON({"R":"Failed","A":"UNAUTHORIZED"})
			rs.Session["User"]=sk[0]
		return None

	def _log_ (self, message, level=0) :
		if level > self.LogLevel :
			print("I","[%d]:%s" % (level,message))

	async def _handle_OPTIONS_ (self, rs) :
		return rs.JSON({"R": "OK"})

	async def _handle_GET_ (self, rio) :
		try :
			p = Path.join(
				self.Home["GET"],
				searchRE("[^/\\\\].*",rio.path).group(0)
			)
		except :
			p = self.Home["GET"]
		if Path.isdir(p) :
			p = Path.join(p, self.Pages["INDEX"])
		return await rio.File(p)

	async def _handle_POST_( self, rio ) :
		try :
			phm = await self.PHMCache.get(Path.join(
				self.Home["POST"],
				searchRE("[^/\\\\].*",rio.path).group(0)
			),reload="NO_API_CACHE" in self.Options and self.Options["NO_API_CACHE"])
			return await phm.handle(rio)
		except Exception as x :
			return rio.JSON({"E": "NO SUCH HANDLER"})

	async def _handle_PUT_ (self, rs) :
		return rs.JSON({"E": "NOT_SUPPORT"})

	async def __handle__ (self, request) :
		try :
			if self.ReqCounts >= self.Options["MAXREQ"] :
				return web.HTTPTooManyRequests()
			self.ReqCounts += 1
			request._client_max_size = self.Options["BUFSIZE"]
			r = RIO(request, self)
			await r.__prepare__()
			## authenticate
			rs = await self._authenticate_(r)
			if rs != None :
				return rs
			## dispatch
			return await getattr(self, "_handle_"+request.method+"_")(r)
		except web.HTTPException as x :
			return x
		except AttributeError as x :
			self._log_(str(x), level=7)
			return web.HTTPBadRequest(reason="Unhandled Method: "+request.method)
		except asyncio.CancelledError :
			await self.stop()
			return web.HTTPBadRequest(reason="Cancelled")
		except XI as x :
			self._log_(str(x), level=7)
			return web.HTTPBadRequest(reason=str(x))
		except Exception as x :
			self._log_(str(x), level=7)
			return web.HTTPBadRequest(reason=str(x))
		finally:
			self.ReqCounts -= 1
		return web.HTTPBadRequest(reason="Unhandle Exception")

	async def __aenter__ (self) :
		try :
			self._log_("Init Host: %s, Port: %d" % (self.Host, self.Port), 9)

			runner = web.ServerRunner(web.Server(self.__handle__))
			await runner.setup()

			host = self.Host
			if host.startswith("[") and host.endswith("]") :
				host = host[1:len(host)-1]
			self.P = web.TCPSite(runner, host, self.Port, ssl_context=self.SSLCtx) if self.SSLCtx else web.TCPSite(runner, host, self.Port)
			await self.P.start()
			self._log_("Ready", 9)
		except Exception as e :
			print("Exception 232", e)
			await self.__aexit__(None, None, None)

	async def __aexit__ (self, type, value, traceback) :
		if self.P :
			await self.P.stop()
			self.P = None

	async def play (self) :
		async with self :
			self.Playing=getLoop().create_future()
			await self.Playing

	def stop (self) :
		self.Playing.set_result(True)
		self.Playing=None
	## }}}

cfg = {
	"host": "0.0.0.0",
	"port": 80,
	"home": {
		"GET": "./GET",
		"POST": "./POST"
	},
	"pages": {
		"INDEX": "index.html"
	},
	"options": {
		"BUFSIZE": 1048576,
		"MAXREQ": 32,
		"MAXREQSIZE": 8388608,
		"NO_API_CACHE": False
	},
	"cors": {
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Headers": "*"
	}
}
config=Path.join(ROOT,argv[1])
cfg["pidfile"]=Path.join(Path.dirname(config),"PWS.pid")
with open(config,"r") as fo :
	cfg.update(json_read(fo));
	for k in cfg["home"] :
		if not cfg["home"][k].startswith("/") :
			cfg["home"][k] = Path.join(ROOT, *[ v for v in cfg["home"][k].split("/") if v ])

makedirs(Path.dirname(cfg["pidfile"]), exist_ok=True)

if "pidfile" in cfg and cfg["pidfile"] :
	try :
		with open(cfg["pidfile"],"w") as fo :
			from os import getpid
			getpid = str(getpid())
			print("PID is %s" % getpid);
			fo.write( getpid )
	except Exception as x :
		print("Exception from daemon: ",x)

ws = PWS(
	host = "%s:%d" % (cfg["host"],cfg["port"]),
	home = cfg["home"],
	pages = cfg["pages"],
	options = cfg["options"],
	cors = cfg["cors"],
	cafiles = (cfg["cert"], cfg["key"]) if "cert" in cfg and cfg["cert"] and "key" in cfg and cfg["key"] else None
)
print(f"Listen on : {cfg['port']}")

signal(SIGINT, lambda sig,frame : ws.stop())

getLoop().run_until_complete(ws.play())

if "pidfile" in cfg and cfg["pidfile"] :
	from os import remove
	remove(cfg["pidfile"])
