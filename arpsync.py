import os, re, sys, socket, select, subprocess, time

excl = os.environ.get("EXC", "~~")
tabl = os.environ.get("TAB", "main")

def secs():
	return int(time.time())

def chks(adrs, addr, dest):
	dchk = (dest + " ")
	if (addr in adrs.keys() and dchk in adrs[addr][0]):
		return True
	return False

def fixs(macs):
	outp = []
	info = macs.split(":")
	for item in info:
		if (len(item) < 2):
			item = ("0" + item)
		outp.append(item)
	return ":".join(outp)

def ecmd(comd, outp=True, bash=False):
	try:
		if (outp):
			return subprocess.check_output(comd, shell=bash)
		else:
			subprocess.Popen(comd, shell=bash, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	except:
		pass
	return b""

def ping(whos):
	adrs = []
	comd = ("awk '{ print $3 }' %s" % (" ".join(whos)))
	info = ecmd(comd, bash=True).decode().split("\n")
	for addr in info:
		if ("." in addr):
			comd = ["ping", "-s", "1", "-c", "1", "-w", "1", "-W", "1", addr]
			ecmd(comd, outp=False)
			adrs.append(addr)
	return adrs

def dels(tabs, addr):
	print(" - "+addr)
	comd = ["ip", "-4", "route", "del", addr, "table", tabs]
	return ecmd(comd)

def adds(tabs, iadr, dadr):
	print(" + "+iadr+" ~ "+dadr)
	comd = ["ip", "-4", "route", "add", iadr, "via", dadr, "table", tabs]
	return ecmd(comd)

def gets(rtab, tabs):
	pres = secs()
	outp = {}
	comd = ["ip", "-4", "route", "show", "table", tabs]
	info = ecmd(comd).decode().replace("\t"," ").lower().strip().split("\n")
	for line in info:
		addr = line.split(" ")[0]
		if ("." in addr):
			outp[addr] = [line, pres]
			if (addr in rtab.keys()):
				outp[addr][1] = rtab[addr][1]
	return outp

def arps(lans, rtab, adrs, intf):
	pres = secs()
	outp = {}
	comd = ["ip", "-4", "neigh", "show", "dev", intf]
	info = ecmd(comd).decode().split("\n")
	for line in info:
		line = (" " + line.replace("?"," ").replace("("," ").replace(")"," ").replace("\t"," ").lower().strip() + " ")
		iadr = re.match("^.*[^0-9]([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}).*$", line)
		madr = re.match("^.*[^0-9a-f]([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}).*$", line)
		exre = re.match("^.*"+excl+".*$", line)
		if (not madr):
			madr = ("*", "*")
		if (iadr and not exre):
			addr = iadr[1]
			macs = madr[1]
			outp[addr] = [macs, pres]
			if (addr in lans.keys()):
				outp[addr][1] = lans[addr][1]
			if (macs != "*"):
				if (chks(rtab, addr, "")):
					dels(tabl, addr)
	for addr in adrs:
		if (not addr in outp.keys()):
			outp[addr] = ["*", pres]
	return outp

def proc(lans, rtab, data, dest):
	pres = secs()
	info = data.split("\n")
	for line in info:
		line = line.split("~")
		if (len(line) > 4):
			mode = line[1]
			addr = line[2]
			macr = line[3]
			if (mode == "a"):
				stat = chks(rtab, addr, dest)
				if (macr == "*"):
					if (stat):
						dels(tabl, addr)
				else:
					if (not stat):
						dels(tabl, addr)
						adds(tabl, addr, dest)
					if (addr in rtab.keys()):
						rtab[addr][1] = pres
				comd = ["ping", "-s", "2", "-c", "1", "-w", "1", "-W", "1", addr]
				ecmd(comd, outp=False)
			if (mode == "r"):
				if (chks(rtab, addr, dest)):
					dels(tabl, addr)
	keys = []
	for addr in rtab.keys():
		if ((pres - rtab[addr][1]) >= 15):
			stat = chks(rtab, addr, dest)
			if (stat):
				dels(tabl, addr)
				keys.append(addr)
	for addr in keys:
		del rtab[addr]
	return (lans, rtab)

def main():
	host = sys.argv[1]
	intf = sys.argv[2]
	dsts = [(args, 31337) for args in sys.argv[3].split(",")]
	whos = [args for args in sys.argv[4].split(",")]

	sent = 0
	wait = 7
	adrs = ping(whos)
	rtab = gets({}, tabl)
	lans = arps({}, rtab, adrs, intf)

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind((host, 31337))

	while True:
		(robj, wobj, eobj) = select.select([sock], [], [], wait)
		pres = secs()

		for objc in robj:
			if (objc == sock):
				(data, addr) = sock.recvfrom(8192)
				if (data):
					try:
						dest = addr[0]
						data = data.decode()
						(lans, rtab) = proc(lans, rtab, data, dest)
					except Exception as e:
						print("recv",e)

		if ((pres - sent) >= wait):
			adrs = ping(whos)
			rtab = gets(rtab, tabl)
			lans = arps(lans, rtab, adrs, intf)
			data = b""
			data += ("\n".join(["~a~"+k+"~"+lans[k][0]+"~" for k in lans.keys()]).encode() + b"\n")
			data += ("\n".join(["~r~"+k+"~"+rtab[k][0]+"~" for k in rtab.keys()]).encode() + b"\n")
			for dest in dsts:
				try:
					send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					send.sendto(data, dest)
					send.close()
				except Exception as e:
					print("send",e)
			sent = pres

		time.sleep(1)

if (__name__ == "__main__"):
	main()
