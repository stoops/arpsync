import os, re, sys, socket, select, subprocess, time

LOOP = 7
EXPR = 17

def secs():
	return int(time.time())

def delk(objc, keys):
	try:
		print(" x ",keys,objc[keys])
		del objc[keys]
	except:
		print("erro","delk",keys)

def chks(maps, addr, dest):
	if (addr in maps.keys()):
		macs = maps[addr][0]
		if ((not dest) or (dest == macs)):
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
			subprocess.Popen(comd, shell=bash, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	except Exception as e:
		print("ecmd",e)
	return b""

def ping(size, addr):
	dest = adrs(addr)
	if (dest):
		comd = ["ping", "-s", str(size), "-c", "1", "-w", "1", "-W", "1", dest]
		ecmd(comd, outp=False, bash=False)

def ecos(whos):
	adrs = []
	comd = ("awk '{ print $3 }' %s" % (" ".join(whos)))
	info = ecmd(comd, outp=True, bash=True).decode().split("\n")
	for addr in info:
		if ("." in addr):
			ping(1, addr)
			adrs.append(addr)
	return adrs

def dels(tabn, addr):
	print(" - ",addr)
	comd = ["ip", "-4", "route", "del", addr, "table", tabn]
	return ecmd(comd, outp=False, bash=False)

def adds(tabn, addr, dest):
	dels(tabn, addr)
	print(" + ",addr,"~",dest)
	comd = ["ip", "-4", "route", "add", addr, "via", dest, "table", tabn]
	return ecmd(comd, outp=False, bash=False)

def tabs(tabl, tabn):
	pres = secs()
	outp = {}
	comd = ["ip", "-4", "route", "show", "table", tabn]
	info = ecmd(comd, outp=True, bash=False)
	info = info.decode().replace("\t", " ").lower().strip().split("\n")
	for line in info:
		temp = line.split(" ")
		addr = temp.pop(0)
		dest = "*"
		if (("/" in addr) or (not "." in addr)):
			continue
		while ((dest == "*") and temp):
			item = temp.pop(0)
			if ((item == "via") and temp):
				dest = temp.pop(0)
				break
		outp[addr] = [dest, pres]
	for addr in tabl.keys():
		if (not addr in outp.keys()):
			outp[addr] = tabl[addr]
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
	#for addr in arpl.keys():
	#	if (not addr in outp.keys()):
	#		outp[addr] = arpl[addr]
	return outp

def send(maps, host, tabn, socs):
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
			delk(arpl, addr)
		if (macs != "*"):
			stat = chks(tabl, addr, "")
			if (stat):
				dels(tabn, addr)
		data += ("~!%s!~a~%s~%s~\n" % (host, addr, macs, )).encode()

	keyl = list(tabl.keys())
	for addr in keyl:
		macs = tabl[addr][0]
		last = tabl[addr][1]
		if ((pres - last) >= EXPR):
			delk(tabl, addr)
		data += ("~!%s!~r~%s~%s~\n" % (host, addr, macs, )).encode()

	if (data):
		try:
			dest = ("255.255.255.255", 31337)
			for sock in socs:
				sock.sendto(data, dest)
		except Exception as e:
			print("send",e)

def proc(maps, host, data, dest, tabn):
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

	for addr in arpr.keys():
		macr = arpr[addr][0]
		stat = chks(tabl, addr, dest)
		if (macr == "*"):
			if (stat):
				dels(tabn, addr)
				delk(tabl, addr)
		else:
			if (not stat):
				adds(tabn, addr, dest)
				tabl[addr] = [dest, pres]
		ping(2, addr)

	for addr in tabr.keys():
		macs = chks(arpl, addr, "")
		if ((not macs) or (macs == "*")):
			stat = chks(tabl, addr, host)
			if (not stat):
				pass
		#		adds(tabn, addr, dest)
		#		tabl[addr] = [dest, pres]
		#ping(3, addr)

	maps[dest] = { "adrl":adrr, "arpl":arpr, "tabl":tabr }

def main():
	excl = os.environ.get("EXC", "~~")
	tabi = os.environ.get("TAB", "main")

	intf = sys.argv[1]
	host = sys.argv[2]
	whos = [args for args in sys.argv[3].split(",")]

	sent = 0
	maps = { host:{ "adrl":[], "tabl":{}, "arpl":{} } }

	socket.SO_BINDTODEVICE = 25

	bind = ("", 31337)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock.bind(bind)

	devs = str(intf+'\0').encode('utf-8')
	socl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socl.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	socl.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, devs)

	bind = (host, 31333)
	socw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socw.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	socw.bind(bind)

	safe = 1
	socs = [socl, socw]
	wait = int(LOOP / 2)
	this = ("!%s!" % (host, )).encode()
	while True:
		(robj, wobj, eobj) = select.select([sock], [], [], wait)
		pres = secs()

		if ((pres - sent) >= LOOP):
			objc = maps[host]
			objc["adrl"] = ecos(whos)
			objc["tabl"] = tabs(objc["tabl"], tabi)
			objc["arpl"] = arps(objc["arpl"], intf, excl)
			send(maps, host, tabi, socs)
			sent = pres

		for objc in robj:
			(data, addr) = objc.recvfrom(8192)
			if ((not data) or (this in data)):
				continue
			print("recv",pres,addr[0],data[:96])
			try:
				dest = addr[0]
				data = data.decode()
				proc(maps, host, data, dest, tabi)
			except Exception as e:
				print("recv",e)

		time.sleep(safe)

if (__name__ == "__main__"):
	main()
