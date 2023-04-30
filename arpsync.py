#!/usr/bin/python3

import os, re, sys, socket, select, subprocess, time
import hmac, hashlib, secrets, ipaddress, queue, threading

SAFE = 0.1337
SLOW = 0.7331
SIZE = 1337
ENCL = (32 + 32)
WAIT = 5
EXPR = 17
NULL = ""
NILL = "*"
SEPR = "@"

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

def ipcs(addr, incl):
	try:
		if (("." in addr) and (not "/" in addr)):
			ipad = ipaddress.ip_address(addr)
			for item in incl:
				netw = ipaddress.ip_network(item)
				if (ipad in netw):
					return True
	except:
		pass
	return False

def chks(maps, addr, dest):
	if (addr in maps.keys()):
		macs = maps[addr][1]
		if (macs == NILL):
			return NULL
		if ((not dest) or (dest == macs)):
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
	return NULL

def arpw(queu: queue.Queue):
	while True:
		try:
			ipvf = queu.get_nowait()
		except:
			break
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
				sock.settimeout(1.5)
				sock.sendto(b"*", (ipvf, 31337))
		except:
			pass

def arpb(ipvl: list[str], maxw: int = 50):
	if not ipvl:
		return
	queu = queue.Queue()
	for ipvf in ipvl:
		queu.put(ipvf)
	numw = min(len(ipvl), maxw)
	for _ in range(numw):
		thrd = threading.Thread(target=arpw, args=(queu, ), daemon=True)
		thrd.start()

def ecmd(comd, outp=True, bash=False):
	try:
		if (outp):
			return subprocess.check_output(comd, shell=bash)
		else:
			return subprocess.Popen(comd, shell=bash, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	except Exception as e:
		print(pdat(),"ecmd",e)
	return b""

def form(pref, valu):
	if (valu):
		return [pref, valu]
	return []

def dels(pref, tabn, addr, intf, mode="del"):
	if (not pref == "send-main"):
		print(pdat()," - ",pref,addr,"~",intf)
	comd = ["ip", "-4", "route", mode, addr] + form("dev", intf) + ["table", tabn]
	pobj = ecmd(comd, outp=False, bash=False)
	if (pobj):
		pobj.wait()

def adds(pref, tabn, addr, intf, dest, mode="replace", prot=""):
	#dels(pref, tabn, addr, intf)
	if (not pref == "send-main"):
		print(pdat()," + ",pref,addr,"~",intf,"~",dest)
	comd = ["ip", "-4", "route", mode, addr] + form("via", dest) + form("dev", intf) + form("proto", prot) + ["table", tabn]
	pobj = ecmd(comd, outp=False, bash=False)
	if (pobj):
		pobj.wait()

def echo(ipsl=[], fill=[]):
	if (fill):
		fnos = " ".join(fill)
		comd = ("awk '{ print $3 }' %s" % (fnos, ))
		ipsl = ecmd(comd, outp=True, bash=True).decode().split("\n")
	(adrs, objs) = ([], [])
	for addr in ipsl:
		if ("." in addr):
			adrs.append(addr)
	if (adrs):
		time.sleep(SLOW)
		arpb(adrs)
	return adrs

def tabz(tabs, ldst, tabn, incl, maps):
	nows = secs()
	outp = {}
	comd = ["ip", "-4", "route", "show", "table", tabn]
	info = ecmd(comd, outp=True, bash=False)
	info = info.decode().replace("\t", " ").lower().strip().split("\n")
	for line in info:
		line = (" " + line.replace("?"," ").replace("("," ").replace(")"," ").replace("\t"," ").lower().strip() + " ")
		iadr = re.match("^[^0-9]([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})[^/].*$", line)
		hadr = re.match("^.*via[^0-9]([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})[^/].*$", line)
		ipre = ipcs(iadr[1], incl) if (iadr) else False
		if (not hadr):
			hadr = (NILL, NILL)
		if (iadr and ipre):
			addr = iadr[1]
			hops = hadr[1]
			kind = "tabz" if ("static" in line) else "tabs"
			when = tabs[addr][3] if ((addr in tabs) and (hops != NILL)) else nows
			outp[addr] = [ldst, hops, kind, when]
	return outp

def arpt(arps, ldst, intf, incl, maps):
	nows = secs()
	outp = {}
	comd = ["ip", "-4", "neigh", "show", "dev", intf]
	info = ecmd(comd, outp=True, bash=False)
	info = info.decode().split("\n")
	for line in info:
		line = (" " + line.replace("?"," ").replace("("," ").replace(")"," ").replace("\t"," ").lower().strip() + " ")
		iadr = re.match("^.*[^0-9]([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}).*$", line)
		madr = re.match("^.*[^0-9a-f]([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}).*$", line)
		ipre = ipcs(iadr[1], incl) if (iadr) else False
		if (not madr):
			madr = (NILL, NILL)
		if (iadr and ipre):
			addr = iadr[1]
			macs = madr[1]
			kind = "arps"
			when = arps[addr][3] if ((addr in arps) and (macs == NILL)) else nows
			outp[addr] = [ldst, macs, kind, when]
	return outp

def ciph(inpt, skey, mode):
	ekey = skey.encode()
	leng = len(inpt)
	if (mode == "e"):
		nows = (int(time.time()) + 1)
		incr = nows.to_bytes(5,byteorder="big")
		init = (secrets.token_bytes(32-len(incr))+incr)
		auth = hashlib.sha256(inpt).digest()
		xori = hmac.new(ekey, msg=init+auth, digestmod=hashlib.sha256).digest()
		xork = hmac.new(ekey, msg=xori+xori, digestmod=hashlib.sha256).digest()
		outp = b""
		for x in range(0, leng, 32):
			xori = hmac.new(ekey, msg=(xori+xork), digestmod=hashlib.sha256).digest()
			xork = hmac.new(ekey, msg=(xork+xori), digestmod=hashlib.sha256).digest()
			for y in range(0, 32, 1):
				if ((x + y) < leng):
					outp += bytes([inpt[x + y] ^ xork[y]])
		return (init + outp + auth)
	if (mode == "d"):
		if (leng <= ENCL):
			return b""
		(init, auth) = (inpt[:32], inpt[-32:])
		incr = int.from_bytes(init[-5:],byteorder="big")
		inpt = inpt[32:-32]
		leng = len(inpt)
		nows = (int(time.time()) - 1)
		if ((incr < nows) or (leng <= 0)):
			return b""
		xori = hmac.new(ekey, msg=init+auth, digestmod=hashlib.sha256).digest()
		xork = hmac.new(ekey, msg=xori+xori, digestmod=hashlib.sha256).digest()
		outp = b""
		for x in range(0, leng, 32):
			xori = hmac.new(ekey, msg=(xori+xork), digestmod=hashlib.sha256).digest()
			xork = hmac.new(ekey, msg=(xork+xori), digestmod=hashlib.sha256).digest()
			for y in range(0, 32, 1):
				if ((x + y) < leng):
					outp += bytes([inpt[x + y] ^ xork[y]])
		csum = hashlib.sha256(outp).digest()
		if (csum != auth):
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
			kind = "arps"
			arpl[ladr] = [ldst, NILL, kind, nows]

	keyl = list(arpl.keys())
	for ladr in keyl:
		objl = arpl[ladr]
		(lsrc, lmac, kind, last) = (objl[0], objl[1], objl[2], objl[3])
		if ((nows - last) >= EXPR):
			keyd("send-arps", arpl, ladr)
			continue
		if (lmac != NILL):
			stat = chks(tabl, ladr, NULL)
			if (stat):
				dels("send-arps", tabn, ladr, None)
				keyd("send-arps", tabl, ladr)
		temp = ("~%s%s%s~a~%s~%s~%s~\n" % (SEPR, ldst, SEPR, ladr, lmac, kind, )).encode()
		if ((len(data) + len(temp) + ENCL) > SIZE):
			outp.append(data) ; data = b""
		data += temp

	keyl = list(tabl.keys())
	for ladr in keyl:
		objl = tabl[ladr]
		(lsrc, lmac, kind, last) = (objl[0], objl[1], objl[2], objl[3])
		if ((nows - last) >= EXPR):
			dels("send-tabs", tabn, ladr, None)
			keyd("send-tabs", tabl, ladr)
			continue
		if (kind != "tabs"):
			continue
		temp = ("~%s%s%s~r~%s~%s~%s~\n" % (SEPR, ldst, SEPR, ladr, lmac, kind, )).encode()
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

def pars(maps, ldst, tabn, data, whos, skey):
	lobj = maps[ldst]
	(adrl, arpl, tabl) = (lobj["adrs"], lobj["arps"], lobj["tabs"])

	(adrr, arpr, tabr) = ([], {}, {})
	if (whos in maps.keys()):
		robj = maps[whos]
		(adrr, arpr, tabr) = (robj["adrs"], robj["arps"], robj["tabs"])

	ipsl = []
	nows = secs()

	info = data.split("\n")
	for line in info:
		line = line.split("~")
		if (len(line) > 5):
			(dstr, tabk, radr, rmac, kind) = (line[1], line[2], line[3], line[4], line[5])
			rdst = dstr.replace(SEPR, NULL)
			if (tabk == "a"):
				arpr[radr] = [rdst, rmac, kind, nows]
			if (tabk == "r"):
				tabr[radr] = [rdst, rmac, kind, nows]
			if (not radr in ipsl):
				ipsl.append(radr)

	keyr = list(arpr.keys())
	for radr in keyr:
		objr = arpr[radr]
		(rdst, rmac, kind, last) = (objr[0], objr[1], objr[2], objr[3])
		if ((nows - last) >= EXPR):
			keyd("pars-arpr", arpr, radr)
			continue
		stat = chks(tabl, radr, rdst)
		if (rmac == NILL):
			if (stat):
				dels("pars-arpr", tabn, radr, None)
				keyd("pars-arpr", tabl, radr)
		else:
			if (not stat):
				adds("pars-arpr", tabn, radr, None, rdst)
			kind = "tabr"
			tabl[radr] = [rdst, rmac, kind, nows]

	keyr = list(tabr.keys())
	for radr in keyr:
		objr = tabr[radr]
		(rsrc, rhop, kind, last) = (objr[0], objr[1], objr[2], objr[3])
		if ((nows - last) >= EXPR):
			keyd("pars-tabr", tabr, radr)
			continue
		if (kind != "tabs"):
			continue
		star = chks(arpl, radr, NULL)
		stat = chks(tabl, radr, NULL)
		if ((rhop != ldst) and (rhop != rsrc) and (not star)):
			if (not stat):
				adds("pars-tabr", tabn, radr, None, rhop, prot="static")
			kind = "tabz"
			tabl[radr] = [rsrc, rhop, kind, last]

	echo(ipsl=ipsl)

	maps[whos] = { "adrs":adrr, "arps":arpr, "tabs":tabr }

def main():
	tabi = os.environ.get("TAB", "main")
	skey = os.environ.get("KEY", "key123")

	lanl = sys.argv[1].split(",")
	wanl = sys.argv[2].split(",")
	incl = sys.argv[3].split(",")
	fill = [args for args in sys.argv[4].split(",")]

	intf = lanl[0]
	ldst = wanl[1]

	sent = 0
	maps = { ldst:{ "adrs":[], "tabs":{}, "arps":{} } }

	bind = (NULL, 31337)
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
	this = ("%s%s%s" % (SEPR, ldst, SEPR, )).encode()
	while True:
		(rfds, wfds, efds) = select.select(socr, [], [], SLOW)
		nows = secs()

		if ((nows - sent) >= WAIT):
			lobj = maps[ldst]
			lobj["adrs"] = echo(fill=fill)
			lobj["tabs"] = tabz(lobj["tabs"], ldst, tabi, incl, maps)
			lobj["arps"] = arpt(lobj["arps"], ldst, intf, incl, maps)
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
