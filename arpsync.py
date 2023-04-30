import os, re, sys, socket, select, subprocess, time
import hmac, hashlib, secrets

SAFE = 0.1337
SLOW = 0.7331
SIZE = 1337
ENCL = (32 + 32)
WAIT = 5
EXPR = 17
NULL = ""
NILL = "*"

def secs():
	return int(time.time())

def pdat():
	return time.strftime("%Y-%m-%d_%H:%M:%S")

def keyd(pref, objc, keys):
	try:
		print(pdat()," x ",pref,keys,objc[keys])
		del objc[keys]
	except:
		print(pdat(),"erro","keyd",pref,keys)

def chks(maps, addr, dest):
	if (addr in maps.keys()):
		macs = maps[addr][0]
		if ((not dest) or (dest == macs)):
			if (macs == NILL):
				return NULL
			return macs
	return NULL

def fixs(macs):
	outp = []
	info = macs.split(":")
	for item in info:
		if (len(item) < 2):
			item = ("0" + item)
		outp.append(item)
	return ":".join(outp)

def adrs(addr):
	try:
		outp = []
		info = addr.split(".")
		for x in range(0, 4):
			nums = info[x][:4]
			outp.append(str(int(nums)))
		return ".".join(outp)
	except:
		pass
	return ""

def ecmd(comd, outp=True, bash=False):
	try:
		if (outp):
			return subprocess.check_output(comd, shell=bash)
		else:
			return subprocess.Popen(comd, shell=bash, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	except Exception as e:
		print(pdat(),"ecmd",e)
	return b""

def ping(size, addr):
	dest = adrs(addr)
	if (dest):
		comd = ["ping", "-s", str(size), "-c", "1", "-w", "1", "-W", "1", dest]
		#print(pdat(),"info",comd)
		return ecmd(comd, outp=False, bash=False)
	return None

def form(pref, intf):
	if (intf):
		return [pref, intf]
	return []

def dels(pref, tabn, addr, intf, mode="del"):
	if (not pref == "send-main"):
		print(pdat()," - ",pref,addr,"~",intf)
	comd = ["ip", "-4", "route", mode, addr] + form("dev", intf) + ["table", tabn]
	pobj = ecmd(comd, outp=False, bash=False)
	if (pobj):
		pobj.wait()

def adds(pref, tabn, addr, intf, dest, mode="replace"):
	#dels(pref, tabn, addr, intf)
	if (not pref == "send-main"):
		print(pdat()," + ",pref,addr,"~",intf,"~",dest)
	comd = ["ip", "-4", "route", mode, addr] + form("via", dest) + form("dev", intf) + ["table", tabn]
	pobj = ecmd(comd, outp=False, bash=False)
	if (pobj):
		pobj.wait()

def echo(whos):
	adrs = []
	objs = []
	fnos = " ".join(whos)
	comd = ("awk '{ print $3 }' %s" % (fnos, ))
	info = ecmd(comd, outp=True, bash=True).decode().split("\n")
	for addr in info:
		if ("." in addr):
			pobj = ping(1, addr)
			objs.append(pobj)
			adrs.append(addr)
	for pobj in objs:
		if (pobj):
			pobj.wait()
	return adrs

def tabr(tabs, tabn):
	nows = secs()
	outp = {}
	comd = ["ip", "-4", "route", "show", "table", tabn]
	info = ecmd(comd, outp=True, bash=False)
	info = info.decode().replace("\t", " ").lower().strip().split("\n")
	for line in info:
		temp = line.split(" ")
		if (not "via" in line):
			continue
		addr = temp.pop(0)
		if ((not "." in addr) or ("/" in addr)):
			continue
		dest = NILL
		while ((dest == NILL) and temp):
			item = temp.pop(0)
			if ((item == "via") and temp):
				dest = temp.pop(0)
				break
		if (dest != NILL):
			outp[addr] = [dest, nows]
	return outp

def arpt(arps, intf, excs):
	nows = secs()
	outp = {}
	comd = ["ip", "-4", "neigh", "show", "dev", intf]
	info = ecmd(comd, outp=True, bash=False)
	info = info.decode().split("\n")
	for line in info:
		line = (" " + line.replace("?"," ").replace("("," ").replace(")"," ").replace("\t"," ").lower().strip() + " ")
		iadr = re.match("^.*[^0-9]([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}).*$", line)
		madr = re.match("^.*[^0-9a-f]([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}).*$", line)
		exre = re.match("^.*"+excs+".*$", line.replace(".", "_"))
		if (not madr):
			madr = (NILL, NILL)
		if (iadr and (not exre)):
			addr = iadr[1]
			macs = madr[1]
			outp[addr] = [macs, nows]
			if (macs == NILL):
				if (addr in arps.keys()):
					outp[addr] = arps[addr]
	return outp

def ciph(inpt, skey, mode):
	ekey = skey.encode()
	leng = len(inpt)
	if (mode == "e"):
		init = secrets.token_bytes(32)
		xork = hmac.new(ekey, msg=init, digestmod=hashlib.sha256).digest()
		outp = b""
		for x in range(0, leng, 32):
			xork = hmac.new(ekey, msg=xork, digestmod=hashlib.sha256).digest()
			for y in range(0, 32):
				if ((x + y) < leng):
					outp += bytes([inpt[x + y] ^ xork[y]])
		auth = hashlib.sha256(inpt).digest()
		return (init + outp + auth)
	if (mode == "d"):
		if (leng <= ENCL):
			return b""
		(init, csum) = (inpt[:32], inpt[-32:])
		inpt = inpt[32:-32]
		leng = len(inpt)
		if (leng <= 0):
			return b""
		xork = hmac.new(ekey, msg=init, digestmod=hashlib.sha256).digest()
		outp = b""
		for x in range(0, leng, 32):
			xork = hmac.new(ekey, msg=xork, digestmod=hashlib.sha256).digest()
			for y in range(0, 32):
				if ((x + y) < leng):
					outp += bytes([inpt[x + y] ^ xork[y]])
		auth = hashlib.sha256(outp).digest()
		if (auth != csum):
			return b""
		return outp

def send(maps, ldst, tabn, iifs, socs, skey):
	lobj = maps[ldst]
	(adrl, arpl, tabl) = (lobj["adrs"], lobj["arps"], lobj["tabs"])

	outp = []
	data = b""
	nows = secs()

	for ladr in adrl:
		if (not ladr in arpl.keys()):
			arpl[ladr] = [NILL, nows]

	keyl = list(arpl.keys())
	for ladr in keyl:
		lmac = arpl[ladr][0]
		last = arpl[ladr][1]
		if ((nows - last) >= EXPR):
			keyd("send-arps", arpl, ladr)
			continue
		if (lmac != NILL):
			stat = chks(tabl, ladr, "")
			if (stat):
				dels("send-arp", tabn, ladr, None)
		temp = ("~@%s@~a~%s~%s~\n" % (ldst, ladr, lmac, )).encode()
		if ((len(data) + len(temp) + ENCL) > SIZE):
			outp.append(data) ; data = b""
		data += temp

	keyl = list(tabl.keys())
	for ladr in keyl:
		lmac = tabl[ladr][0]
		last = tabl[ladr][1]
		if ((nows - last) >= EXPR):
			keyd("send-tabs", tabl, ladr)
			continue
		temp = ("~@%s@~r~%s~%s~\n" % (ldst, ladr, lmac, )).encode()
		if ((len(data) + len(temp) + ENCL) > SIZE):
			outp.append(data) ; data = b""
		data += temp

	if (data):
		outp.append(data) ; data = b""

	for x in range(0, len(outp)):
		outp[x] = ciph(outp[x], skey, "e")
	time.sleep(SLOW)
	if (outp):
		uniq = []
		for x in range(0, len(iifs)):
			sock = socs[x]
			intf = iifs[x]
			if (intf[0] in uniq):
				continue
			dest = ("255.255.255.255", 31337)
			tabn = "main"
			adds("send-main", tabn, dest[0], intf[0], None, mode="add")
			try:
				for data in outp:
					sock.sendto(data, dest)
			except Exception as e:
				print(pdat(),"erro","send-proc",intf,e)
			dels("send-main", tabn, dest[0], intf[0])
			uniq.append(intf[0])

def pars(maps, ldst, tabn, data, rdst, skey):
	lobj = maps[ldst]
	(adrl, arpl, tabl) = (lobj["adrs"], lobj["arps"], lobj["tabs"])

	(adrr, arpr, tabr) = ([], {}, {})
	if (rdst in maps.keys()):
		robj = maps[rdst]
		(adrr, arpr, tabr) = (robj["adrs"], robj["arps"], robj["tabs"])

	ecos = []
	nows = secs()

	info = data.split("\n")
	for line in info:
		line = line.split("~")
		if (len(line) > 4):
			(whos, kind, radr, rmac) = (line[1], line[2], line[3], line[4])
			if (kind == "a"):
				arpr[radr] = [rmac, nows]
			if (kind == "r"):
				tabr[radr] = [rmac, nows]
			if (not radr in ecos):
				ecos.append(radr)

	keyr = list(arpr.keys())
	for radr in keyr:
		rmac = arpr[radr][0]
		last = arpr[radr][1]
		if ((nows - last) >= EXPR):
			keyd("pars-arps", arpr, radr)
			continue
		stat = chks(tabl, radr, rdst)
		if (rmac == NILL):
			if (stat):
				dels("pars-arps", tabn, radr, None)
				keyd("pars-arps", tabl, radr)
		else:
			if (not stat):
				adds("pars-arps", tabn, radr, None, rdst)
				tabl[radr] = [rdst, nows]

	objs = []
	for radr in ecos:
		if ("." in radr):
			pobj = ping(3, radr)
			objs.append(pobj)
	time.sleep(SLOW)
	for pobj in objs:
		if (pobj):
			pobj.wait()

	maps[rdst] = { "adrs":adrr, "arps":arpr, "tabs":tabr }

def main():
	excl = os.environ.get("EXC", "~~").replace(".", "_")
	tabi = os.environ.get("TAB", "main")
	skey = os.environ.get("KEY", "key123")

	lanl = sys.argv[1].split(",")
	wanl = sys.argv[2].split(",")
	whos = [args for args in sys.argv[3].split(",")]

	intf = lanl[0]
	ldst = wanl[1]

	sent = 0
	maps = { ldst:{ "adrs":[], "tabs":{}, "arps":{} } }

	bind = ("", 31337)
	socl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	socl.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	socl.bind(bind)

	devs = str(intf+"\0").encode("utf-8")
	socd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	socd.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	socd.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, devs)

	bind = (ldst, 31333)
	socb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	socb.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	socb.bind(bind)

	socr = [socl]
	socw = [socd, socb]
	iifs = [lanl, wanl]
	this = ("@%s@" % (ldst, )).encode()
	while True:
		(rfds, wfds, efds) = select.select(socr, [], [], SLOW)
		nows = secs()

		if ((nows - sent) >= WAIT):
			lobj = maps[ldst]
			lobj["adrs"] = echo(whos)
			lobj["tabs"] = tabr(lobj["tabs"], tabi)
			lobj["arps"] = arpt(lobj["arps"], intf, excl)
			send(maps, ldst, tabi, iifs, socw, skey)
			sent = nows

		for sock in rfds:
			(data, addr) = sock.recvfrom(1900)
			data = ciph(data, skey, "d")
			if ((not data) or (this in data)):
				continue
			print(pdat(),"recv",len(data),addr[0],data[:96])
			try:
				rdst = addr[0]
				data = data.decode()
				pars(maps, ldst, tabi, data, rdst, skey)
			except Exception as e:
				print(pdat(),"erro","recv",e)

		time.sleep(SAFE)

if (__name__ == "__main__"):
	socket.SO_BINDTODEVICE = 25
	main()
