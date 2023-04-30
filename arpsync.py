import os, re, sys, socket, select, subprocess, time

LOOP = 7
EXPR = 17

def secs():
	return int(time.time())

def delk(pref, objc, keys):
	try:
		print(" x ",pref,keys,objc[keys])
		del objc[keys]
	except:
		print("erro","delk",pref,keys)

def chks(maps, addr, dest):
	if (addr in maps.keys()):
		macs = maps[addr][0]
		if ((not dest) or (dest == macs)):
			if (macs == "*"):
				return ""
			return macs
	return ""

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
		print("ecmd",e)
	return b""

def ping(size, addr):
	dest = adrs(addr)
	if (dest):
		comd = ["ping", "-s", str(size), "-c", "1", "-w", "1", "-W", "1", dest]
		#print("info",comd)
		return ecmd(comd, outp=False, bash=False)
	return None

def form(pref, intf):
	if (intf):
		return [pref, intf]
	return []

def dels(tabn, addr, intf):
	print(" - ",addr,"~",intf)
	comd = ["ip", "-4", "route", "del", addr] + form("dev", intf) + ["table", tabn]
	pobj = ecmd(comd, outp=False, bash=False)
	if (pobj):
		pobj.wait()

def adds(tabn, addr, intf, dest):
	dels(tabn, addr, intf)
	print(" + ",addr,"~",intf,"~",dest)
	comd = ["ip", "-4", "route", "add", addr] + form("via", dest) + form("dev", intf) + ["table", tabn]
	pobj = ecmd(comd, outp=False, bash=False)
	if (pobj):
		pobj.wait()

def reps(tabn, addr, intf):
	comd = ["ip", "-4", "route", "replace", addr] + form("dev", intf) + ["table", tabn]
	pobj = ecmd(comd, outp=False, bash=False)
	if (pobj):
		pobj.wait()

def ecos(whos):
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

def tabs(tabl, tabn):
	pres = secs()
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
		dest = "*"
		while ((dest == "*") and temp):
			item = temp.pop(0)
			if ((item == "via") and temp):
				dest = temp.pop(0)
				break
		if (dest != "*"):
			outp[addr] = [dest, pres]
	return outp

def arps(arpl, intf, excs):
	pres = secs()
	outp = {}
	comd = ["ip", "-4", "neigh", "show", "dev", intf]
	info = ecmd(comd, outp=True, bash=False)
	info = info.decode().split("\n")
	for line in info:
		line = (" " + line.replace("?"," ").replace("("," ").replace(")"," ").replace("\t"," ").lower().strip() + " ")
		iadr = re.match("^.*[^0-9]([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}).*$", line)
		madr = re.match("^.*[^0-9a-f]([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}).*$", line)
		exre = re.match("^.*"+excs+".*$", line)
		if (not madr):
			madr = ("*", "*")
		if (iadr and (not exre)):
			addr = iadr[1]
			macs = madr[1]
			outp[addr] = [macs, pres]
			if (macs == "*"):
				if (addr in arpl.keys()):
					outp[addr] = arpl[addr]
	return outp

def send(maps, host, tabn, iifs, socs):
	pres = secs()
	data = b""
	objc = maps[host]
	(adrl, arpl, tabl) = (objc["adrl"], objc["arpl"], objc["tabl"])
	for addr in adrl:
		if (not addr in arpl.keys()):
			arpl[addr] = ["*", pres]

	keyl = list(arpl.keys())
	for addr in keyl:
		macs = arpl[addr][0]
		last = arpl[addr][1]
		if ((pres - last) >= EXPR):
			delk("send-arp", arpl, addr)
		if (macs != "*"):
			stat = chks(tabl, addr, "")
			if (stat):
				dels(tabn, addr, None)
		data += ("~!%s!~a~%s~%s~\n" % (host, addr, macs, )).encode()

	keyl = list(tabl.keys())
	for addr in keyl:
		macs = tabl[addr][0]
		last = tabl[addr][1]
		if ((pres - last) >= EXPR):
			delk("send-tab", tabl, addr)
		data += ("~!%s!~r~%s~%s~\n" % (host, addr, macs, )).encode()

	if (data):
		for x in range(0, len(iifs)):
			intf = iifs[x]
			dest = ("255.255.255.255", 31337)
			adds("main", dest[0], intf[0], None)
			time.sleep(0.25)
			try:
				socs[x].sendto(data, dest)
			except Exception as e:
				print("erro","send-proc",intf,e)
			dels("main", dest[0], intf[0])

def proc(maps, host, data, dest, tabn):
	seen = []
	pres = secs()
	objc = maps[host]
	(adrl, arpl, tabl) = (objc["adrl"], objc["arpl"], objc["tabl"])

	info = data.split("\n")
	(adrr, arpr, tabr) = ([], {}, {})
	for line in info:
		line = line.split("~")
		if (len(line) > 4):
			(whos, mode, addr, macr) = (line[1], line[2], line[3], line[4])
			if (mode == "a"):
				arpr[addr] = [macr, pres]
			if (mode == "r"):
				tabr[addr] = [macr, pres]

	objs = []
	for addr in arpr.keys():
		macr = arpr[addr][0]
		stat = chks(tabl, addr, dest)
		if (macr == "*"):
			if (stat):
				dels(tabn, addr, None)
				delk("proc-arp", tabl, addr)
		else:
			if (not stat):
				adds(tabn, addr, None, dest)
				tabl[addr] = [dest, pres]
		if (not addr in seen):
			pobj = ping(2, addr)
			objs.append(pobj)
			seen.append(addr)

	for addr in tabr.keys():
		if (not addr in seen):
			pobj = ping(3, addr)
			objs.append(pobj)
			seen.append(addr)

	for pobj in objs:
		if (pobj):
			pobj.wait()

	maps[dest] = { "adrl":adrr, "arpl":arpr, "tabl":tabr }

def main():
	excl = os.environ.get("EXC", "~~")
	tabi = os.environ.get("TAB", "main")

	lanl = sys.argv[1].split(",")
	wanl = sys.argv[2].split(",")
	whos = [args for args in sys.argv[3].split(",")]

	intf = lanl[0]
	host = wanl[1]

	sent = 0
	maps = { host:{ "adrl":[], "tabl":{}, "arpl":{} } }

	bind = ("", 31337)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock.bind(bind)

	devs = str(intf+'\0').encode('utf-8')
	socl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	socl.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	socl.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, devs)

	bind = (host, 31333)
	socw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	socw.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	socw.bind(bind)

	safe = 1
	socr = [sock]
	socs = [socl, socw]
	iifs = [lanl, wanl]
	wait = int(LOOP / 2)
	this = ("!%s!" % (host, )).encode()
	while True:
		(robj, wobj, eobj) = select.select(socr, [], [], wait)
		pres = secs()

		if ((pres - sent) >= LOOP):
			objc = maps[host]
			objc["adrl"] = ecos(whos)
			objc["tabl"] = tabs(objc["tabl"], tabi)
			objc["arpl"] = arps(objc["arpl"], intf, excl)
			send(maps, host, tabi, iifs, socs)
			sent = pres

		for objc in robj:
			(data, addr) = objc.recvfrom(8192)
			#print("debg",data)
			if ((not data) or (this in data)):
				continue
			print("recv",pres,addr[0],data[:96])
			try:
				dest = addr[0]
				data = data.decode()
				proc(maps, host, data, dest, tabi)
			except Exception as e:
				print("erro","recv",e)

		time.sleep(safe)

if (__name__ == "__main__"):
	socket.SO_BINDTODEVICE = 25
	main()
