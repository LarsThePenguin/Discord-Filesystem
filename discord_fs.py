########################
#  Discord Filesystem  #
# By: Lars the Penguin #
########################

# CONFIGURATION #

# Bot token
TOKEN = "DISCORD_BOT_TOKEN_HERE"

# ID of the channel you want the messages to be sent to and read from
CHANNEL_ID = 0 # Discord Channel ID here

maxCacheSize = 4 # This is in Gibibytes
cacheDirectoryName = "Cache\\"
maxFileSize = 20_000_000

saveFile = "files.pickle"

# END OF CONFIGURATION #

from winfspy import FileSystem, enable_debug_log
import discord, pickle
from winfspy.memfs import *
import threading, time, os
from textwrap import wrap

client = discord.Client(intents=discord.Intents.default(), max_messages=20)
global channel
backslash = "\\" # Just for compatibility with Python versions before 3.12

deleteOldestFile = False

cacheEnabled = False

currentWriteSpeed = 0
timeSpentReading = 0
currentReadSpeed = 0
timeSpentWriting = 0
writeInProgress = False
readInProgress = False

try:
	open(saveFile, "rb")
except:
	with open(saveFile, "w") as f:
		f.write("")

def addToReadSpeed(numb):
	global currentReadSpeed, printCurrentReadSpeed
	currentReadSpeed += numb

def addToWriteSpeed(numb):
	global currentWriteSpeed, printCurrentWriteSpeed
	currentWriteSpeed += numb

def addToTimeSpentReading(numb):
	global timeSpentReading
	timeSpentReading += numb

def addToTimeSpentWriting(numb):
	global timeSpentWriting
	timeSpentWriting += numb

async def asyncListToList(asyncList) -> list:
	return [gen async for gen in asyncList]

def strToBytearray(string: str) -> bytearray:
	returnVal = bytearray(len(string))
	for i in range(len(string)):
		returnVal[i] = string[i]
	return returnVal

def runAsyncFunction(func):
	task = client.loop.create_task(func)
	while not task.done():
		pass
	result = task.result()
	return result

def macroForPickle(self):
	try:
		with open(saveFile, "rb") as fr:
			stuff = pickle.load(fr)
			if type(self) == DiscordFile:
				stuff[str(self.path)] = self.get_file_info()
				stuff[str(self.path)]["IDs"] = self.IDs
				with open(saveFile, "wb") as fw:
					pickle.dump(stuff, fw)
			elif type(self) == DiscordFolderObj:
				stuff[str(self.path)] = self.get_file_info()
				with open(saveFile, "wb") as fw:
					pickle.dump(stuff, fw)
	except EOFError:
		stuff = {}
		if type(self) == DiscordFile:
			stuff[str(self.path)] = self.get_file_info()
			stuff[str(self.path)]["IDs"] = self.IDs
			with open(saveFile, "wb") as fw:
				pickle.dump(stuff, fw)
		elif type(self) == DiscordFolderObj:
			stuff[str(self.path)] = self.get_file_info()
			with open(saveFile, "wb") as fw:
				pickle.dump(stuff, fw)

def pickleRead(path):
	try:
		with open(saveFile, "rb") as fr:
			stuff = pickle.load(fr)
			print(str(path))
			print(stuff)
			return stuff[str(path)]
	except EOFError:
		return None
	except KeyError:
		return None

def readFile(listOfMessageIDs: list) -> bytearray:
	messages = runAsyncFunction(asyncListToList(channel.history(limit=46116000000)))
	returnData = bytearray(0)
	for message in messages:
		start = time.time()
		startSize = len(returnData)
		if message.id in listOfMessageIDs:
			for i in message.attachments:
				currentData = runAsyncFunction(i.read())
				returnData += currentData
		addToReadSpeed((len(returnData)-startSize)/(time.time() - start + 0.01))
	return returnData

def uploadFile(data: bytearray) -> list:
	chunks = wrap(data.decode("latin-1"), maxFileSize)
	messageIDs = []
	for chunk in chunks:
		start = time.time()
		file = open("upldchk.tmp.txt", "wb")
		file.write(bytes(chunk, encoding="latin-1"))
		file.close()
		message = runAsyncFunction(channel.send(file=discord.File("upldchk.tmp.txt")))
		messageIDs.append(message.id)
		os.remove("upldchk.tmp.txt")
		addToWriteSpeed(len(chunk)/(time.time() - start + 0.01))
	return messageIDs

class DiscordBaseFileObj(object):
	@property
	def name(self):
		"""File name, without the path"""
		return self.path.name

	@property
	def file_name(self):
		"""File name, including the path"""
		return str(self.path)

	def __init__(self, path, attributes, security_descriptor):
		path = Path(path)
		self.path = path
		self.attributes = attributes
		self.security_descriptor = security_descriptor
		now = filetime_now()
		self.creation_time = now
		self.last_access_time = now
		self.last_write_time = now
		self.change_time = now
		self.index_number = 0
		self.file_size = 0

	def get_file_info(self):
		return {
			"path": self.path,
			"attributes": self.attributes,
			"allocation_size": self.allocation_size,
			"file_size": self.file_size,
			"creation_time": self.creation_time,
			"last_access_time": self.last_access_time,
			"last_write_time": self.last_write_time,
			"change_time": self.change_time,
			"index_number": self.index_number,
			"security_descriptor": SecurityDescriptor.to_string(self.security_descriptor)
		}

	def __repr__(self):
		return f"{type(self).__name__}:{self.file_name}"

class DiscordFolderObj(DiscordBaseFileObj):
	def __init__(self, path, attributes, security_descriptor):
		path = Path(path)
		hehe = pickleRead(path)
		if hehe == None:
			super().__init__(path, attributes, security_descriptor)
			self.allocation_size = 0
			assert self.attributes & FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY
		else:
			super().__init__(path, attributes, security_descriptor)
			for i in hehe.keys():
				if i == "security_descriptor":
					self.security_descriptor = SecurityDescriptor.from_string(hehe[i])
				else:
					setattr(self, i, hehe[i])

class DiscordFile(DiscordBaseFileObj):

	allocation_unit = 4096

	def __init__(self, path, attributes=None, security_descriptor=None, allocation_size=0):
		hehe = pickleRead(path)
		if hehe == None:
			super().__init__(path, attributes, security_descriptor)
			self.attributes |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE
			self.IDs = []
			self.isCached = False
			self.cacheLastAccess = 0
			self.path = path
			self.attributesForSaving = attributes
			macroForPickle(self)
		else:
			for i in hehe.keys():
				if i == "allocation_size":
					self.file_size = hehe[i]
				elif i == "security_descriptor":
					self.security_descriptor = SecurityDescriptor.from_string(hehe[i])
				else:
					setattr(self, i, hehe[i])

	@property
	def allocation_size(self):
		return self.file_size
	
	def set_allocation_size(self, allocation_size):
		if allocation_size < self.allocation_size:
			data = readFile(self.IDs)
			data = data[:allocation_size]
			self.IDs = uploadFile(data)
			macroForPickle(self)
		if allocation_size > self.allocation_size:
			data = readFile(self.IDs)
			try:
				data += bytearray(allocation_size - self.allocation_size)
			except MemoryError:
				print("Error: Not enough RAM to transfer file, this can be fixed (in code) by only downloading/uploading the modified parts of the file, that would require a overhaul of how file IDs are stored, storing the areas of the file that each ID stores.")
			self.IDs = uploadFile(data)
		macroForPickle(self)
		self.file_size = min(self.file_size, allocation_size)

	def adapt_allocation_size(self, file_size):
		units = (file_size + self.allocation_unit - 1) // self.allocation_unit
		self.set_allocation_size(units * self.allocation_unit)

	def set_file_size(self, file_size):
		if file_size < self.file_size:
			zeros = bytearray(self.file_size - file_size)
			data = readFile(self.IDs)
			data[file_size:self.file_size] = zeros
			self.IDs = uploadFile(data)
			macroForPickle(self)
		if file_size > self.allocation_size:
			self.adapt_allocation_size(file_size)
		self.file_size = file_size

	def read(self, offset, length):
		global readInProgress
		readInProgress = True
		startTime = time.time()
		if offset >= self.file_size:
			raise NTStatusEndOfFile()
		end_offset = min(self.file_size, offset + length)
		if cacheEnabled == True:
			if not self.isCached:
				data = readFile(self.IDs)[offset:end_offset]
				data = bytes(data)
				readInProgress = False
				return data
			else:
				data = open(f"{cacheDirectoryName}{str(self.path).replace(backslash, '_')}", "rb").read()[offset:end_offset]
				self.cacheLastAccess = time.time()
				readInProgress = False
				return data
		else:
			data = readFile(self.IDs)[offset:end_offset]
			data = bytes(data)
			readInProgress = False
			return data

	def write(self, buffer, offset, write_to_end_of_file):
		global deleteOldestFile
		global writeInProgress
		writeInProgress = True
		# This function and the constrained_write function can be optimized by uploading only the changed parts, not the entire file.
		# ^ but I'll do that later
		startTime = time.time()
		if write_to_end_of_file:
			offset = self.file_size
		end_offset = offset + len(buffer)
		if end_offset > self.file_size:
			self.set_file_size(end_offset)
		if cacheEnabled == True:
			if self.isCached:
				file = open(f"{cacheDirectoryName}{str(self.path).replace(backslash, '_')}", "wb+")
				file.seek(offset)
				file.write(buffer)
				data = file.read()
				data[offset:end_offset] = buffer
				self.IDs = uploadFile(data)
				if sum(d.stat().st_size for d in os.scandir(cacheDirectoryName) if d.is_file()) > maxCacheSize*1_073_741_824:
					deleteOldestFile = True
			else:
				data = readFile(self.IDs)
				data[offset:end_offset] = buffer
				file = open(f"{cacheDirectoryName}{str(self.path).replace(backslash, '_')}", "wb")
				file.seek(offset)
				file.write(buffer)
				self.IDs = uploadFile(data)
				if self.isCached == False:
					self.isCached = True
				if sum(d.stat().st_size for d in os.scandir(cacheDirectoryName) if d.is_file()) > maxCacheSize*1_073_741_824:
					deleteOldestFile = True
		else:
			data = readFile(self.IDs)
			data[offset:end_offset] = buffer
			self.IDs = uploadFile(data)
		macroForPickle(self)
		writeInProgress = False
		return len(buffer)

	def constrained_write(self, buffer, offset):
		global deleteOldestFile
		global writeInProgress
		writeInProgress = True
		if offset >= self.file_size:
			return 0
		end_offset = min(self.file_size, offset + len(buffer))
		transferred_length = end_offset - offset
		if cacheEnabled == True:
			if self.isCached:
				file = open(f"{cacheDirectoryName}{str(self.path).replace(backslash, '_')}", "wb+")
				file.seek(offset)
				file.write(buffer)
				data = file.read()
				data[offset:end_offset] = buffer[:transferred_length]
				self.IDs = uploadFile(data)
				if sum(d.stat().st_size for d in os.scandir(cacheDirectoryName) if d.is_file()) > maxCacheSize*1_073_741_824:
					deleteOldestFile = True
			else:
				data = readFile(self.IDs)
				data[offset:end_offset] = buffer[:transferred_length]
				file = open(f"{cacheDirectoryName}{str(self.path).replace(backslash, '_')}", "wb")
				file.seek(offset)
				file.write(buffer)
				self.IDs = uploadFile(data)
				if self.isCached == False:
					self.isCached = True
				if sum(d.stat().st_size for d in os.scandir(cacheDirectoryName) if d.is_file()) > maxCacheSize*1_073_741_824:
					deleteOldestFile = True
		else:
			data = readFile(self.IDs)
			data[offset:end_offset] = buffer[:transferred_length]
			self.IDs = uploadFile(data)
		macroForPickle(self)
		writeInProgress = False
		return transferred_length
	
	def uploadFileAndSetIDs(self):
		# This will only be used if a cached file is being removed from cache
		data = readFile(self.IDs) # Note (Fix later), should read from cache (disk), not from Discord
		self.IDs = uploadFile(data)
	
class DiscordVirtualDisk(InMemoryFileSystemOperations):
	def __init__(self, sizeInGB = 16, read_only=False):
		super().__init__("")

		max_file_nodes = 1024
		max_file_size = sizeInGB * 1024 * 1024
		file_nodes = 0

		self._volume_info = {
			"total_size": max_file_nodes * max_file_size,
			"free_size": (max_file_nodes - file_nodes) * max_file_size,
			"volume_label": "Quite large",
		}

		self.read_only = read_only
		self._root_path = PureWindowsPath("/")
		self._root_obj = FolderObj(
			self._root_path,
			FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
			SecurityDescriptor.from_string("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"),
		)
		self._entries = {self._root_path: self._root_obj}
		try:
			stuff = pickle.load(open(saveFile, "rb"))
			print(stuff.keys())
			if stuff == None:
				raise
			for i in stuff.keys():
				if "IDs" in list(stuff[i].keys()):
					self._entries[Path(stuff[i]["path"])] = DiscordFile(PureWindowsPath(stuff[i]["path"]))
				elif "IDs" not in list(stuff[i].keys()):
					self._entries[Path(stuff[i]["path"])] = DiscordFolderObj(PureWindowsPath(stuff[i]["path"]))
		except:
			macroForPickle(self._root_obj)
		self._thread_lock = threading.Lock()
		if cacheEnabled:
			threading.Thread(target=self.deleteOldFilesThread).start()

	def deleteOldFilesThread(self):
		global deleteOldestFile
		while True:
			if deleteOldestFile == True:
				list_of_files = os.listdir(cacheDirectoryName)
				full_path = [cacheDirectoryName+"{0}".format(x) for x in list_of_files]
				oldest_file = min(full_path, key=os.path.getctime)
				for i in self._entries:
					if isinstance(i, DiscordFile) and f"{cacheDirectoryName}{str(i.path).replace(backslash, '_')}" == oldest_file:
						i.uploadFileAndSetIDs()
						deleteOldestFile = False
						break
				os.remove(oldest_file)

	def _import_files(self, file_path):
		file_path = Path(file_path)
		path = self._root_path / file_path.name
		obj = DiscordFile(
			path,
			FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE,
			self._root_obj.security_descriptor,
		)
		self._entries[path] = obj
		obj.write(file_path.read_bytes(), 0, False)

	@operation
	def rename(self, file_context, file_name, new_file_name, replace_if_exists):
		if self.read_only:
			raise NTStatusMediaWriteProtected()

		file_name = PureWindowsPath(file_name)
		new_file_name = PureWindowsPath(new_file_name)

		# Retrieve file
		try:
			file_obj = self._entries[file_name]

		except KeyError:
			raise NTStatusObjectNameNotFound()

		if new_file_name in self._entries:
			# Case-sensitive comparison
			if new_file_name.name != self._entries[new_file_name].path.name:
				pass
			elif not replace_if_exists:
				raise NTStatusObjectNameCollision()
			elif not isinstance(file_obj, DiscordFile):
				raise NTStatusAccessDenied()

		for entry_path in list(self._entries):
			try:
				relative = entry_path.relative_to(file_name)
				new_entry_path = new_file_name / relative
				entry = self._entries.pop(entry_path)
				entry.path = new_entry_path
				self._entries[new_entry_path] = entry
			except ValueError:
				continue

	@operation
	def create(
		self,
		file_name,
		create_options,
		granted_access,
		file_attributes,
		security_descriptor,
		allocation_size,
	):
		if self.read_only:
			raise NTStatusMediaWriteProtected()

		file_name = PureWindowsPath(file_name)

		# `granted_access` is already handle by winfsp
		# `allocation_size` useless for us

		# Retrieve file
		try:
			parent_file_obj = self._entries[file_name.parent]
			if isinstance(parent_file_obj, DiscordFile):
				raise NTStatusNotADirectory()
		except KeyError:
			raise NTStatusObjectNameNotFound()

		# File/Folder already exists
		if file_name in self._entries:
			raise NTStatusObjectNameCollision()

		if create_options & CREATE_FILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE:
			file_obj = self._entries[file_name] = DiscordFolderObj(
				file_name, file_attributes, security_descriptor
			)
		else:
			file_obj = self._entries[file_name] = DiscordFile(
				file_name,
				file_attributes,
				security_descriptor,
				allocation_size,
			)

		return OpenedObj(file_obj)

	@operation
	def read_directory(self, file_context, marker):
		entries = []
		file_obj = file_context.file_obj

		# Not a directory
		if isinstance(file_obj, DiscordFile):
			raise NTStatusNotADirectory()

		# The "." and ".." should ONLY be included if the queried directory is not root
		if file_obj.path != self._root_path:
			parent_obj = self._entries[file_obj.path.parent]
			entries.append({"file_name": ".", **file_obj.get_file_info()})
			entries.append({"file_name": "..", **parent_obj.get_file_info()})

		# Loop over all entries
		for entry_path, entry_obj in self._entries.items():
			try:
				relative = entry_path.relative_to(file_obj.path)
			# Filter out unrelated entries
			except ValueError:
				continue
			# Filter out ourself or our grandchildren
			if len(relative.parts) != 1:
				continue
			# Add direct chidren to the entry list
			entries.append({"file_name": entry_path.name, **entry_obj.get_file_info()})

		# Sort the entries
		entries = sorted(entries, key=lambda x: x["file_name"])

		# No filtering to apply
		if marker is None:
			return entries

		# Filter out all results before the marker
		for i, entry in enumerate(entries):
			if entry["file_name"] == marker:
				return entries[i + 1 :]

	@operation
	def cleanup(self, file_context, file_name, flags) -> None:
		if self.read_only:
			raise NTStatusMediaWriteProtected()

		# TODO: expose FspCleanupDelete & friends
		FspCleanupDelete = 0x01
		FspCleanupSetAllocationSize = 0x02
		FspCleanupSetArchiveBit = 0x10
		FspCleanupSetLastAccessTime = 0x20
		FspCleanupSetLastWriteTime = 0x40
		FspCleanupSetChangeTime = 0x80
		file_obj = file_context.file_obj

		# Delete
		if flags & FspCleanupDelete:

			# Check for non-empty direcory
			if any(key.parent == file_obj.path for key in self._entries):
				return

			# Delete immediately
			try:
				del self._entries[file_obj.path]
			except KeyError:
				raise NTStatusObjectNameNotFound()

		# Resize
		if flags & FspCleanupSetAllocationSize:
			file_obj.adapt_allocation_size(file_obj.file_size)

		# Set archive bit
		if flags & FspCleanupSetArchiveBit and isinstance(file_obj, DiscordFile):
			file_obj.attributes |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE

		# Set last access time
		if flags & FspCleanupSetLastAccessTime:
			file_obj.last_access_time = filetime_now()

		# Set last access time
		if flags & FspCleanupSetLastWriteTime:
			file_obj.last_write_time = filetime_now()

		# Set last access time
		if flags & FspCleanupSetChangeTime:
			file_obj.change_time = filetime_now()

def handleYesNo(prompt):
	while True:
		result = input(prompt)
		if result.lower() == "y":
			return True
		elif result.lower() == "n":
			return False
		elif result.lower() == "yes":
			return True
		elif result.lower() == "no":
			return False
		else:
			print("Incorrect response, please try again")
	

def runVirtualDisk():
	testing = False
	debug = False
	if debug:
		enable_debug_log()
	mountpoint = Path("X:")
	is_drive = mountpoint.parent == mountpoint
	reject_irp_prior_to_transact0 = not is_drive and not testing
	global timeSpentReading, currentReadSpeed
	global timeSpentWriting, currentWriteSpeed
	global cacheEnabled
	fs = FileSystem(
		str(mountpoint),
		DiscordVirtualDisk(1024*1024*1024),
		sector_size=512,
		sectors_per_allocation_unit=1,
		volume_creation_time=filetime_now(),
		volume_serial_number=0,
		file_info_timeout=1000,
		case_sensitive_search=1,
		case_preserved_names=1,
		unicode_on_disk=1,
		persistent_acls=1,
		post_cleanup_when_modified_only=1,
		um_file_context_is_user_context2=1,
		file_system_name=str(mountpoint),
		prefix="",
		debug=debug,
		reject_irp_prior_to_transact0=reject_irp_prior_to_transact0,
		# security_timeout_valid=1,
		# security_timeout=10000,
	)
	try:
		print("""
_____________________________________________
| WELCOME TO THE DISCORD FILESYSTEM PROJECT |
|           BY: LARS THE PENGUIN            |
‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
""")

		cacheEnabled = handleYesNo("Enable cache? (y/n): ")

		print("Starting File System...")
		fs.start()
		print("Started File System")
		startTime = time.time()
		while True:
			print(f"Timestamp {round(time.time()-startTime)} speeds: - - - {round(currentReadSpeed/1_024, 1)} KiB/s reads - - - {round(currentWriteSpeed/1_024, 1)} KiB/s writes"+str(" - - - Write in progress" if writeInProgress else "")+(" - - - Read in progress" if readInProgress else ""))
			currentReadSpeed = 0
			currentWriteSpeed = 0
			timeSpentReading = 0
			timeSpentWriting = 0
			time.sleep(10)
	except KeyboardInterrupt:
		print("Stopping File System...")
		fs.stop()
		print("Stopped File System")

@client.event
async def on_ready():
	global channel
	channel = client.get_channel(CHANNEL_ID)
	threading.Thread(target=runVirtualDisk).start()

client.run(TOKEN, log_handler=None)
