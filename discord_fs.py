###############################
# Discord Filesystem Win v1.5 #
#     By: Lars the Penguin    #
###############################

# CONFIGURATION #


# Bot token
TOKEN = "DISCORD_BOT_TOKEN_HERE"

# ID of the channel you want the messages to be sent to and read from
CHANNEL_ID = 0 # CHANNEL ID HERE

maxCacheSize = 4 # This is in Gibibytes
cacheDirectoryName = "Cache\\" # The directory that cached files are stored
maxFileSize = 20_000_000 # The size of spilts for uploading to Discord

saveFile = "files.pickle" # The file where the IDs of the files should be saved


# END OF CONFIGURATION #

from winfspy import FileSystem, BaseFileSystemOperations, FILE_ATTRIBUTE, CREATE_FILE_CREATE_OPTIONS, NTStatusObjectNameNotFound, NTStatusDirectoryNotEmpty, NTStatusNotADirectory, NTStatusObjectNameCollision, NTStatusAccessDenied, NTStatusEndOfFile, NTStatusMediaWriteProtected, enable_debug_log
from winfspy.plumbing.security_descriptor import SecurityDescriptor
from winfspy.plumbing.win32_filetime import filetime_now
import threading, time, os, discord, pickle, logging
from pathlib import Path, PureWindowsPath
from functools import wraps
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

def operation(fn):
	"""Decorator for file system operations.

	Provides both logging and thread-safety
	"""
	name = fn.__name__

	@wraps(fn)
	def wrapper(self, *args, **kwargs):
		head = args[0] if args else None
		tail = args[1:] if args else ()
		try:
			with self._thread_lock:
				result = fn(self, *args, **kwargs)
		except Exception as exc:
			logging.info(f" NOK | {name:20} | {head!r:20} | {tail!r:20} | {exc!r}")
			raise
		else:
			logging.info(f" OK! | {name:20} | {head!r:20} | {tail!r:20} | {result!r}")
			return result

	return wrapper

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
				stuff[str(self.path)] = self.get_file_info_for_pickle()
				stuff[str(self.path)]["IDs"] = self.IDs
				stuff[str(self.path)]["isCached"] = self.isCached
				with open(saveFile, "wb") as fw:
					pickle.dump(stuff, fw)
			elif type(self) == DiscordFolderObj:
				stuff[str(self.path)] = self.get_file_info_for_pickle()
				with open(saveFile, "wb") as fw:
					pickle.dump(stuff, fw)
	except EOFError:
		stuff = {}
		if type(self) == DiscordFile:
			stuff[str(self.path)] = self.get_file_info_for_pickle()
			stuff[str(self.path)]["IDs"] = self.IDs
			stuff[str(self.path)]["isCached"] = self.isCached
			with open(saveFile, "wb") as fw:
				pickle.dump(stuff, fw)
		elif type(self) == DiscordFolderObj:
			stuff[str(self.path)] = self.get_file_info_for_pickle()
			with open(saveFile, "wb") as fw:
				pickle.dump(stuff, fw)

def pickleRead(path):
	try:
		with open(saveFile, "rb") as fr:
			stuff = pickle.load(fr)
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

class DiscordBaseFileObj:
	@property
	def name(self):
		"""File name, without the path"""
		return self.path.name

	@property
	def file_name(self):
		"""File name, including the path"""
		return str(self.path)

	def __init__(self, path, attributes, security_descriptor):
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

	def get_file_info_for_pickle(self):
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

	def get_file_info(self):
		return {
			"file_attributes": self.attributes,
			"allocation_size": self.allocation_size,
			"file_size": self.file_size,
			"creation_time": self.creation_time,
			"last_access_time": self.last_access_time,
			"last_write_time": self.last_write_time,
			"change_time": self.change_time,
			"index_number": self.index_number,
		}

	def __repr__(self):
		return f"{type(self).__name__}:{self.file_name}"

class OpenedObj:
	def __init__(self, file_obj):
		self.file_obj = file_obj

	def __repr__(self):
		return f"{type(self).__name__}:{self.file_obj.file_name}"

class DiscordFolderObj(DiscordBaseFileObj):
	def __init__(self, path, attributes=None, security_descriptor=None):
		hehe = pickleRead(path)
		if hehe == None:
			super().__init__(path, attributes, security_descriptor)
			self.allocation_size = 0
			macroForPickle(self)
		else:
			for i in hehe.keys():
				if i == "security_descriptor":
					self.security_descriptor = SecurityDescriptor.from_string(hehe[i])
				else:
					setattr(self, i, hehe[i])
		assert self.attributes & FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY

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
				print("Error: Not enough RAM to transfer file.")
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
				data = readFile(self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)])[offset-int(offset/maxFileSize)*maxFileSize:end_offset-int(end_offset/maxFileSize)*maxFileSize]
				data = bytes(data)
				file = open(f"{cacheDirectoryName}{str(self.path).replace(backslash, '_')}", "wb")
				file.seek(offset)
				file.write(data)
				readInProgress = True
				return data
			else:
				file = open(f"{cacheDirectoryName}{str(self.path).replace(backslash, '_')}", "rb")
				file.seek(offset)
				data = file.read(length)
				self.cacheLastAccess = time.time()
				readInProgress = False
				return data
		else:
			data = readFile(self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)])[offset-int(offset/maxFileSize)*maxFileSize:end_offset-int(end_offset/maxFileSize)*maxFileSize]
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
				file.seek(int(offset/maxFileSize)*maxFileSize)
				data = file.read(int(end_offset/maxFileSize)*maxFileSize-len(buffer))
				data[offset-int(offset/maxFileSize)*maxFileSize:end_offset-int(end_offset/maxFileSize)*maxFileSize] = buffer
				self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)] = uploadFile(data)
				if sum(d.stat().st_size for d in os.scandir(cacheDirectoryName) if d.is_file()) > maxCacheSize*1_073_741_824:
					deleteOldestFile = True
			else:
				data = readFile(self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)])
				data[offset-int(offset/maxFileSize)*maxFileSize:end_offset-int(end_offset/maxFileSize)*maxFileSize] = buffer
				file = open(f"{cacheDirectoryName}{str(self.path).replace(backslash, '_')}", "wb")
				file.seek(offset)
				file.write(buffer)
				self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)] = uploadFile(data)
				if self.isCached == False:
					self.isCached = True
				if sum(d.stat().st_size for d in os.scandir(cacheDirectoryName) if d.is_file()) > maxCacheSize*1_073_741_824:
					deleteOldestFile = True
		else:
			data = readFile(self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)])
			data[offset-int(offset/maxFileSize)*maxFileSize:end_offset-int(end_offset/maxFileSize)*maxFileSize] = buffer
			self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)] = uploadFile(data)
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
			data = readFile(self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)])
			data[offset-int(offset/maxFileSize)*maxFileSize:end_offset-int(end_offset/maxFileSize)*maxFileSize] = buffer[:transferred_length]
			self.IDs[int(offset/maxFileSize):int(end_offset/maxFileSize)] = uploadFile(data)
		macroForPickle(self)
		writeInProgress = False
		return transferred_length
	
	def uploadFileAndSetIDs(self):
		# This will only be used if a cached file is being removed from cache
		data = readFile(self.IDs) # Note (Fix later), should read from cache (disk), not from Discord
		self.IDs = uploadFile(data)
	
class DiscordVirtualDisk(BaseFileSystemOperations):
	def __init__(self, sizeInGB = 16, read_only=False):
		super().__init__()

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
		self._root_obj = DiscordFolderObj(
			self._root_path,
			FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
			SecurityDescriptor.from_string("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"),
		)
		self._entries = {self._root_path: self._root_obj}
		try:
			stuff = pickle.load(open(saveFile, "rb"))
			if stuff == None:
				raise
			for i in stuff.keys():
				if "IDs" in list(stuff[i].keys()):
					self._entries[Path(stuff[i]["path"])] = DiscordFile(Path(stuff[i]["path"]))
				else:
					self._entries[Path(stuff[i]["path"])] = DiscordFolderObj(Path(stuff[i]["path"]))
		except Exception as e:
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

	def _create_directory(self, path):
		path = self._root_path / path
		obj = DiscordFolderObj(
			path,
			FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
			self._root_obj.security_descriptor,
		)
		self._entries[path] = obj

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
	def get_volume_info(self):
		return self._volume_info

	@operation
	def set_volume_label(self, volume_label):
		self._volume_info["volume_label"] = volume_label

	@operation
	def get_security_by_name(self, file_name):
		file_name = PureWindowsPath(file_name)

		# Retrieve file
		try:
			file_obj = self._entries[file_name]
		except KeyError:
			raise NTStatusObjectNameNotFound()

		return (
			file_obj.attributes,
			file_obj.security_descriptor.handle,
			file_obj.security_descriptor.size,
		)

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
				stuff = pickle.load(open(saveFile, "rb"))
				del stuff[str(entry.path)]
				pickle.dump(stuff, open(saveFile, "wb"))
				entry.path = new_entry_path
				self._entries[new_entry_path] = entry
				macroForPickle(entry)
			except ValueError:
				continue

	@operation
	def get_security(self, file_context):
		return file_context.file_obj.security_descriptor

	@operation
	def set_security(self, file_context, security_information, modification_descriptor):
		if self.read_only:
			raise NTStatusMediaWriteProtected()

		new_descriptor = file_context.file_obj.security_descriptor.evolve(
			security_information, modification_descriptor
		)
		file_context.file_obj.security_descriptor = new_descriptor

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
	def open(self, file_name, create_options, granted_access):
		file_name = PureWindowsPath(file_name)

		# `granted_access` is already handle by winfsp

		# Retrieve file
		try:
			file_obj = self._entries[file_name]
		except KeyError:
			raise NTStatusObjectNameNotFound()

		return OpenedObj(file_obj)

	@operation
	def close(self, file_context):
		pass

	@operation
	def get_file_info(self, file_context):
		return file_context.file_obj.get_file_info()


	@operation
	def set_basic_info(
		self,
		file_context,
		file_attributes,
		creation_time,
		last_access_time,
		last_write_time,
		change_time,
		file_info,
	) -> dict:
		if self.read_only:
			raise NTStatusMediaWriteProtected()

		file_obj = file_context.file_obj
		if file_attributes != FILE_ATTRIBUTE.INVALID_FILE_ATTRIBUTES:
			file_obj.attributes = file_attributes
		if creation_time:
			file_obj.creation_time = creation_time
		if last_access_time:
			file_obj.last_access_time = last_access_time
		if last_write_time:
			file_obj.last_write_time = last_write_time
		if change_time:
			file_obj.change_time = change_time

		return file_obj.get_file_info()

	@operation
	def set_file_size(self, file_context, new_size, set_allocation_size):
		if self.read_only:
			raise NTStatusMediaWriteProtected()

		if set_allocation_size:
			file_context.file_obj.set_allocation_size(new_size)
		else:
			file_context.file_obj.set_file_size(new_size)

	@operation
	def can_delete(self, file_context, file_name: str) -> None:
		file_name = PureWindowsPath(file_name)

		# Retrieve file
		try:
			file_obj = self._entries[file_name]
		except KeyError:
			raise NTStatusObjectNameNotFound

		if isinstance(file_obj, DiscordFolderObj):
			for entry in self._entries.keys():
				try:
					if entry.relative_to(file_name).parts:
						raise NTStatusDirectoryNotEmpty()
				except ValueError:
					continue

	@operation
	def get_dir_info_by_name(self, file_context, file_name):
		path = file_context.file_obj.path / file_name
		try:
			entry_obj = self._entries[path]
		except KeyError:
			raise NTStatusObjectNameNotFound()

		return {"file_name": file_name, **entry_obj.get_file_info()}

	@operation
	def read(self, file_context, offset, length):
		return file_context.file_obj.read(offset, length)

	@operation
	def write(self, file_context, buffer, offset, write_to_end_of_file, constrained_io):
		if self.read_only:
			raise NTStatusMediaWriteProtected()

		if constrained_io:
			return file_context.file_obj.constrained_write(buffer, offset)
		else:
			return file_context.file_obj.write(buffer, offset, write_to_end_of_file)

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
				stuff = pickle.load(open(saveFile, "rb"))
				del stuff[str(file_obj.path)]
				pickle.dump(stuff, open(saveFile, "wb"))
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

	@operation
	def overwrite(
		self, file_context, file_attributes, replace_file_attributes: bool, allocation_size: int
	) -> None:
		if self.read_only:
			raise NTStatusMediaWriteProtected()

		file_obj = file_context.file_obj

		# File attributes
		file_attributes |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE
		if replace_file_attributes:
			file_obj.attributes = file_attributes
		else:
			file_obj.attributes |= file_attributes

		# Allocation size
		file_obj.set_allocation_size(allocation_size)

		# Set times
		now = filetime_now()
		file_obj.last_access_time = now
		file_obj.last_write_time = now
		file_obj.change_time = now

	@operation
	def flush(self, file_context) -> None:
		pass

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
	mountpoint = Path("Z:")
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
