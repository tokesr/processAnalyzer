import csv
import json
import difflib
import requests
import time
import argparse



# C:\ProgramData\osquery>osqueryi.exe -csv "select p.pid, p.name, p.path, p.parent, p.cmdline, p.start_time, p.elapsed_time,
# p.on_disk, h.md5, h.sha256 from processes p left outer join hash h on p.path=h.path" > output_wc1

global ADAPTING
# investigating filename masquerading with types (similar filenames)

global VERBOSE
# show verbose output logs


class Process:
	def __init__(self, pid, ppid, name, \
		path, cmdline, start_time, elapsed_time, on_disk, md5, sha256, dicts):
		self.pid = pid
		self.ppid = ppid
		self.name = name
		self.path = path
		self.cmdline = cmdline
		self.start_time = start_time
		self.elapsed_time = elapsed_time
		self.on_disk = on_disk
		self.md5 = md5
		self.sha256 = sha256

		self.parent = None
		self.children = []

		self.suspiciousness = 0
		self.suspComment= []

		self.dicts = dicts
		self.indent = -1

		
	def setIndent(self):
		if (self.parent == None):
			self.indent = 0
		elif(self.pid == self.ppid):
			self.indent = 0
		else:
			self.indent = self.parent.setIndent() + 1
		return self.indent

	def jsonify(self):
		json_block = {"pid":self.pid, "parent":self.ppid, "name":self.name, "path":self.path, \
		"cmdline": self.cmdline, "start_time": self.start_time, "elapsed_time":self.elapsed_time,\
		"on_disk":self.on_disk, "md5":self.md5, "sha256":self.sha256}
		if (len(self.children) > 0 and self.pid!= self.ppid):
			json_block["children"]=[child.jsonify() for child in self.children]
		return json_block


def createProcessFromCsv(csv_file, delimiter):
	csvreader = csv.DictReader(open(csv_file,"r"),delimiter=delimiter)
	tmp_list = []
	for row in csvreader:
		tmp_list.append(Process(row['pid'], row['parent'], row['name'], row['path'], row['cmdline'], \
			row['start_time'], row['elapsed_time'], row['on_disk'], row['md5'], row['sha256'], row))
	return tmp_list



def findParents(process_list):
	for process in process_list:
		parent_id = process.ppid
		for parent in process_list:
			if (parent.pid == parent_id):
				process.parent = parent
				break
			process.parent = None



def findChildren(process_list):
	for process in process_list:
		for child in process_list:
			if (child.parent != None and process.pid == child.parent.pid):
				process.children.append(child)




def globalSetIndent(process_list):
	for process in process_list:
		process.setIndent()




def createJson(process_list):
	jsonOutput = []
	for process in process_list:
		if(process.indent == 0):
			jsonOutput.append(process.jsonify())

	print(json.dumps(jsonOutput, indent=max(process.indent for process in process_list )))
	#TODO: indent can be 0 when writing into a file


def analizeProcess(proc, known_processes, process_list, mode, adapted_name=None):
	# checking 4 things so far
	# 1: amount of processes with the same name, 1: there can be maximum 1, 2: any amount
	# 2: location - if known - is correct
	# 3: parent - if known - is correct
	# 4: find similarly named Win files (detection evasion)
	# 5: on_disk? - way too FP-prone
	# TODO: random path recognition - FP-prone
	if(adapted_name == None):
		process_name = proc.name.lower()
	else:
		verbosePrint("Adapting. Changing the checkable name from: "+proc.name + " to: " \
			+ adapted_name + " .")
		process_name = adapted_name.lower()


	baseline_process = None;
	for baseline in known_processes:
		if(process_name == baseline['name'].lower()):
			baseline_process = baseline


	if(baseline_process):
		#amount of processes with the same name
		#only if there are a process in the know_processes list
		if (int(baseline_process['number']) == 1):	
			counter = 0	
			for process in process_list:
				if(process.name.lower() == process_name):
					counter = counter + 1

			if(counter > 1 and mode == 'analyze'):
				proc.suspiciousness = proc.suspiciousness + 1
				proc.suspComment.append("One too many processes with the same name.")

		#location check
		# if the baseline_process location field is empty it means, we do not care with the parent
		match = 0
		if(len(baseline_process['location']) == 0):
			#empty list means we don't care with the location
			match = 1

		if(not match):
			for loc in baseline_process['location']:
				if(proc.path.lower() == loc.lower()):
					#"" mean location is not found by osquery, doesn't mean its wrong
					# "" in the baseline_process means: non-found location ok, wrong location not ok
					# empty list in baseline means no location check at all
					match = 1
					break

		if(not match and mode == 'analyze'):
			proc.suspiciousness = proc.suspiciousness + 1
			proc.suspComment.append("Incorrect location. Process location: " + proc.path)			

		if(not match and mode == 'learning'):
			# add a new location
			loc = baseline_process['location']
			loc.append(proc.path.lower())
			baseline_process.update({'location':loc})


		#parent check
		#TODO: only checks the name and not the path, full path should be checked
		match = 0

		if(len(baseline_process['parent']) == 0):
			#empty list means we don't care with the parent
			match = 1

		if(not match):
			for parent in baseline_process['parent']:
				if((proc.parent != None and proc.parent.name == parent ) \
					or (proc.parent == None  and parent == "" )):
					#empty mean location is not found by osquery, doesn't mean its wrong
					match = 1
					break


		if(not match and mode == 'analyze' ):
			proc.suspiciousness = proc.suspiciousness + 1
			proc.suspComment.append("Incorrect parent.")

		if(not match and mode == 'learning' and proc.parent != None):	
			par = baseline_process['parent']
			if(proc.parent):
				par.append(proc.parent.name.lower())
			else:
				par.append("")
			baseline_process.update({'parent':par})


	elif (baseline_process == None and mode == 'learning'):
		# if there is no entry for this one in the file
		# and we are in a learning mode, then create a new json entry
		new_process_entry = {}
		new_process_entry['name'] = process_name
		new_process_entry['number'] = 2 # 2 mean unlimited and there is no proper way to decrease it
		new_process_entry['location'] = [proc.path,""]
		if(proc.parent != None):
			new_process_entry['parent'] = [proc.parent.name,""]
		else:
			new_process_entry['parent'] = [""]
		known_processes.append(new_process_entry)




	else:
	#find similarly Windows files with Lavenshtien
	# if there is a match we can adapt the whole thing to check that as well
	# no reason to check it if there is a windows filename with the same name, thus the if
		for known in known_processes:
			sequence = difflib.SequenceMatcher(None, process_name, known['name'].lower())
			ratio = sequence.ratio()*100
			if(ratio > 85 and ratio < 100):
				if(mode == 'analyze'):
					proc.suspiciousness = proc.suspiciousness + 1
					proc.suspComment.append("Possible name alteration: proc name: "+ proc.name + \
						" Win proc name: " +known['name'])
				if(ADAPTING):
					print("ADAPTING: " + str(ADAPTING))
					analizeProcess(proc, known_processes, process_list, mode, adapted_name=known['name'].lower())



	#on_disk
	# if executed file is not on the disk it can be suspicious
	# malwares can try to evade AV detection this way
	# -1 = not found by osquery
	# 0 = not on the disk, suspicious
	# 1 = on the disk, don't care

	if(proc.on_disk == 0):
			proc.suspiciousness = proc.suspiciousness + 1
			proc.suspComment.append("Executable does not exists on the disk")	



	return known_processes




def checkOnVirusTotal(apikey, process_list, hashfile):
	#don't request the same hashes over and over again, not efficient, build a table

	hash_cache = [] # building a cache, so same hashes don't have to be looked up again
	hash_list = [] # permanently saved hashes from a file, save them to a file
	done = False

	if(hashfile != ""):
		try:
			with open(hashfile, "r") as hf:
				hash_list=hf.read().splitlines()
		except FileNotFoundError:
			print("Error: provided hashfile not found. No input hash.")
			pass;


	for process in process_list:
		for hash_a in [process.md5, process.sha256]:
			done = False
			for saved_hash in hash_list:
				if (hash_a == saved_hash):
					done = True

			if not done:
				for cached_hash in hash_cache:
					# is the hash in the cashe
					if(hash_a == cached_hash['hash_a']):
						done = True
						verbosePrint("Hash: " +hash_a +" is cached.")

						if(int(cached_hash['positives']) > 5):
							process.suspiciousness = process.suspiciousness + 1
							process.suspComment.append("Malicious hash: " + hash_a + \
									" ratio: " + str(cached_hash['positives']) + "\\" \
									+ str(cached_hash['total']) +".")
							verbosePrint(process.suspComment[-1])


				#if it is not in the cache:
				while(not done and hash_a!=""):
					url = 'https://www.virustotal.com/vtapi/v2/file/report'
					params = {'apikey': apikey, 'resource': hash_a}
					response = requests.get(url, params=params)
					verbosePrint("Hash: " +hash_a +" downloaded/under download.")
					if(response.status_code != 200 ):
						verbosePrint("Waiting 30 secs.")
						time.sleep(30)
					else:
						done = True
						response = response.json()
						if(response['response_code'] == 1):
							hash_cache.append({'hash_a':hash_a, 'positives':response['positives'] \
								, 'total':response['total']})

							if(int(response['positives']) > 5):
								process.suspiciousness = process.suspiciousness + 1
								process.suspComment.append("Malicious hash: " + hash_a + \
								" ratio: " + str(response['positives']) + "\\" \
								+ str(response['total']) +".")
								verbosePrint(process.suspComment[-1])


	if(hashfile != ""):
		with open(hashfile, "a+") as hf:
			for hash_entity in hash_cache:
				if(hash_entity['positives']<=5):
					hf.write(str(hash_entity['hash_a']) +"\n")





def verbosePrint(output):
	if (VERBOSE):
		print(str(output))
	else:
		return











def main():
	global ADAPTING
	global VERBOSE

	### ARGUMENT PARSING
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", "--delimiter", help="delimiter for the csv file", default="|")
	parser.add_argument("-s", "--systemroot", \
		help="root directory of the original system, default=C:\\windows\\", \
		default="C:\\windows\\")
	parser.add_argument("-a", "--adapting", \
		help="comparing filenames to similar known files to detect evasion attempt (can be slow)",\
	 default=False, action="store_true")
	parser.add_argument("-v", "--verbose", \
		help="verbose",\
	 default=False, action="store_true")
	parser.add_argument("-k", "--apikey", \
		help="apikey for virustotal lookup, without it virustotal won't be utilized",\
	 default="")
	parser.add_argument("-c", "--cachefile", \
		help="you can load known hashes from a file, these ones aren't going to be checked on VT",\
	 default="")
	parser.add_argument("-p", "--processfile", \
		help="file for a list of known Windows processes, default: known_processes.json",\
	 default="known_processes.json")
	parser.add_argument("-o", "--outputfile", \
		help="output file for the json output, or for the result of the analysis",\
	 default="")


	requiredArguments = parser.add_argument_group('required arguments')
	requiredArguments.add_argument("-i", "--input", help="path to the csv file", required=True)
	requiredArguments.add_argument("-m", "--mode", choices=('json','analyze', 'learning'), required=True, \
		help="choose json to print a json process tree, or analyze to analyze the processes")




	args = parser.parse_args()



	delimiter = args.delimiter
	csv_filename = args.input
	SystemRoot = args.systemroot	

	VERBOSE = args.verbose
	ADAPTING = args.adapting
	apikey = args.apikey
	hashfile = args.cachefile
	processfile = args.processfile
	function = args.mode
	outputfile = args.outputfile # not used yet

	### /ARGUMENT PARSING


	known_processes = {}


	#---------- NEEDED for every function -----------#
	process_list = createProcessFromCsv(csv_filename,delimiter)
	findParents(process_list)
	findChildren(process_list)



	#print(str(entropy("chphlpgkkbolifaimnlloiipkdnihall")))
	#for entropy, not monitoring C:\Windows\Temp\

	if(function == "json"):
		#----------- NEEDED for json---------------------#
		globalSetIndent(process_list)		
		createJson(process_list)

	elif(function == "analyze" or function == 'learning'):
		try:
			with open(processfile,'r') as json_file:  
				known_processes = json.load(json_file)
		except:
			known_processes = []

		for entry in known_processes:
			#TODO: parent should be checked as well
			#TODO: this should be changed back when writing the thing back to a file
			#TODO: known processes can't be empty right now, should be error-handled
			if(isinstance(entry['location'],list)):
				loc_list = []
				for loc in entry['location']:
					loc_list.append(loc.replace('%SystemRoot%\\',SystemRoot))
				entry.update({'location':loc_list})


		if(apikey != "" and function == "analyze"):
			checkOnVirusTotal(apikey, process_list, hashfile)		

		for test_proc in process_list:
			known_processes = analizeProcess(test_proc, known_processes, process_list, function)
			if(test_proc.suspiciousness > 0 and function == 'analyze'):
				print("PID: "+str(test_proc.pid))
				print("Name: "+test_proc.name)
				print("Location: " + str(test_proc.path))
				for msg in test_proc.suspComment:		
					print(msg)
				print("\n\n")

		if(function == 'learning'):
			with open(processfile, 'w+') as outfile:  
				json.dump(known_processes, outfile, indent=3)
		



if __name__== "__main__":
  main()
