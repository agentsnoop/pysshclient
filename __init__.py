# This is a test
import time
import os
import socket
import tempfile

import paramiko
from scp import SCPClient

from response import Response

CMD_PS_GREP		= "ps -lfp {pid} | grep {pid}"

class SshClient(object):

	def __init__(self, host, port=22, user="root", password=None, timeout=5, load_keys=False):
		self._client 		= None
		self._scp_client	= None
		self._host			= host
		self._port			= port
		self._user			= user
		self._password		= password
		self._timeout		= timeout
		self._load_keys		= load_keys

	@property
	def connected(self):
		if self._client:
			try:
				transport = self._client.get_transport()
				if transport and transport.is_active():
					transport.send_ignore()
					return True
			except EOFError as e:
				pass
		return False

	def connect(self, retry_count=5):
		self._client = paramiko.SSHClient()
		self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		if self._password is None:
			self._client.load_system_host_keys()

		if not self._client:
			return False

		attempt = 0
		while attempt < retry_count:
			if self._connect():
				return True
			attempt += 1
			time.sleep(5.0)
		return False

	def _connect(self):
		try:
			self._client.connect(
				self._host,
				self._port,
				self._user,
				self._password,
				timeout=self._timeout,
				allow_agent=(self._password is None),
				look_for_keys=(self._password is None))
			# self._client.get_transport().set_keepalive(1)
			# if self._scp_client:
			# 	self._scp_client = SCPClient(self._client.get_transport())
			return True
		except paramiko.BadHostKeyException as e1:
			print("Bad Host Key for {host}:{port} as {user}: {error}".format(host=self._host, port=self._port, user=self._user, error=e1))
		except paramiko.AuthenticationException as e2:
			print("Bad Authentication for {host}:{port} as {user}: {error}".format(host=self._host, port=self._port, user=self._user, error=e2))
		except paramiko.SSHException as e3:
			print("SSH Exception for {host}:{port} as {user}: {error}".format(host=self._host, port=self._port, user=self._user, error=e3))
		except socket.error as e4:
			print("Socket error for {host}:{port} as {user}: {error}".format(host=self._host, port=self._port, user=self._user, error=e4))
		except Exception as e5:
			print(type(e5))
			print("Unable to connect to {host}:{port} as {user}: {error}".format(host=self._host, port=self._port, user=self._user, error=e5))
		return False

	def disconnect(self):
		"""Disconnect SSH session, if active"""
		if self._client:
			try:
				self._client.close()
			except Exception:
				pass
		self._client = None

	def run_and_wait(self, command, search, max_time=60, redirect=""):
		(pid,) = self.run(command, redirect, background=True, max_wait=5)
		return self.wait_for_remote_task(pid, search, max_time=max_time)

	def run(self, command, redirect="", background=False, max_wait=None):
		"""
		Run command on remote machine. Output redirection, whether to run in the background, 
		how long to wait for output, and the response type can all be set.
		
		:param string command: Command to execute remotely
		:param string redirect: Output redirect paramters, if desired.
		:param boolean background: Whether or not to run the command in the background, and not wait for the result of the command.
		:param float max_wait: Maximum time to wait for output from the command. None allows for an unlimited amount of time.
		:param int response_type: Which data to output from the command. Logical or values together to get more data
		:return: One or more values based on response type: (RES_PID, RES_CODE, RES_SUCCESS, RES_STDOUT, RES_STDERR)
		:rtype: tuple
		"""
		stdout 			= None
		stderr 			= None
		pid				= -1
		code 			= -999
		pre_command		= "echo $$; exec"
		post_command	= ""
		if background:
			redirect	= "> /dev/null 2>&1" if not redirect else redirect
			parts 		= redirect.split()
			if parts[0] != ">":
				parts.insert(0, ">")
			if len(parts) == 3 and parts[2] != "2>&1":
				parts[2] = "2>&1"
			if len(parts) == 2:
				parts.append("2>&1")
			redirect = " ".join(parts)
			pre_command		= ""
			post_command	= "& echo $!"

		if self.connected or self.connect():
			try:
				tmp_file = None
				if "&&" in command or "||" in command or ";" in command:
					tmp_file = tempfile.NamedTemporaryFile(delete=False)
					tmp_file.write("#!/bin/sh\n\n")
					tmp_file.write(command)
					tmp_file.close()
					self.put_file(tmp_file.name, "/tmp")
					os.unlink(tmp_file.name)
					# self._client.exec_command("echo '#!/bin/sh\n\n{command}' > /tmp/cmd.sh; chmod +x /tmp/cmd.sh".format(command=command))
					command = "sh /tmp/{filename}".format(filename=os.path.basename(tmp_file.name))

				cmd = "{pre} {command} {redirect} {post}".format(pre=pre_command, command=command, redirect=redirect, post=post_command)
				start_time = time.time()
				stdin_obj, stdout_obj, stderr_obj = self._client.exec_command(cmd)

				# If channel stays open longer than desired
				while max_wait and not stdout_obj.channel.eof_received:
					time.sleep(1)
					if time.time() - start_time > max_wait:
						stdout_obj.channel.close()
						if not stderr_obj.channel.eof_received:
							stderr_obj.channel.close()
						break

				code 	= stdout_obj.channel.recv_exit_status()
				stderr 	= stderr_obj.readlines()
				stdout 	= stdout_obj.readlines()
				if stdout:
					pid 	= stdout[0].strip()
					stdout 	= [l.strip() for l in stdout[1:]]
				if stderr:
					stderr	= [l.strip() for l in stderr]

				if tmp_file:
					self._client.exec_command("rm -f /tmp/{filename}".format(filename=os.path.basename(tmp_file.name)))
			except Exception as e:
				print("Encountered a problem while performing SSH ({command}): {error}".format(command=command, error=str(e)))

		return Response(obj=None, pid=pid, code=code, stdout=stdout, stderr=stderr)

	# def get_file(self, src, dst, verify=False):
	# 	return scp_io.get_file(src, dst, self._host, self._port, self._user, self._password)

	# def put_file(self, src, dst, owner=None, group=None, verify=False):
	# 	return scp_io.put_file(src, dst, self._host, self._port, self._user, self._password, owner=owner, group=group)

	def get_file(self, src, dst, recursive=False, preserve_times=False, verify=False):
		try:
			if not self._scp_client:
				self._scp_client = SCPClient(self._client.get_transport())
			self._scp_client.get(remote_path=src, local_path=dst, recursive=recursive, preserve_times=preserve_times)
			return True
		except Exception as e:
			print("Encountered a problem while doing SCP: {error}".format(error=str(e)))
			self._scp_client = None
		return False

	def put_file(self, src, dst="", permissions=None, owner=None, group=None, max_sessions=999, preserve_times=False, verify=False):
		if not self._create_parent(dst, max_sessions):
			return False

		try:
			if not self._scp_client:
				self._scp_client = SCPClient(self._client.get_transport())
			self._scp_client.put(src, remote_path=dst, recursive=os.path.isdir(src), preserve_times=preserve_times)
		except Exception as e:
			print("Encountered a problem performing SCP: {error}".format(error=str(e)))
			self._scp_client = None
			return False

		self._set_permission(owner, group, permissions, dst, max_sessions)
		return True

	def get_file2(self, src, dst, checksum=None, max_attempts=None):
		try:
			if not self._scp_client:
				self._scp_client = SCPClient(self._client.get_transport())
		except Exception as e:
			try:
				self._scp_client = SCPClient(self._client.get_transport())
			except Exception as e:
				print("Encountered a problem while doing SCP: {error}".format(error=str(e)))
				return False

		file_io.makedirs(os.path.dirname(dst))
		if not checksum:
			checksum = self.get_checksum(src)

		success = os.path.exists(dst) and file_io.get_md5(dst) == checksum
		if success:
			print("{dst} already present...skipping".format(dst=dst))
			return True

		print("Getting {src} --> {dst}".format(src=src, dst=dst))
		attempts = 0
		while not success:
			attempts += 1
			if max_attempts and attempts > max_attempts:
				return False

			self._scp_client.get(remote_path=src, local_path=dst)
			success = file_io.get_md5(dst) == checksum
			time.sleep(1)
		return True

	def put_file2(self, src, dst="", checksum=None, max_attempts=None, owner=None, group=None, permissions=None, max_sessions=999):
		try:
			if not self._scp_client:
				self._scp_client = SCPClient(self._client.get_transport())
		except Exception as e:
			try:
				self._scp_client = SCPClient(self._client.get_transport())
			except Exception as e:
				print("Encountered a problem while doing SCP: {error}".format(error=str(e)))
				return False

		if not self._create_parent(dst, max_sessions):
			return False
		self.run("chown -R {owner}:{group} {path}".format(owner=owner, group=group, path=dst))

		if not checksum:
			checksum = file_io.get_md5(src)

		success = self.get_checksum(dst) == checksum
		if success:
			print("{dst} already present...skipping".format(dst=dst))
			return True

		print("Putting {src} --> {dst}".format(src=src, dst=dst))
		attempts = 0
		while not success:
			attempts += 1
			if max_attempts and attempts > max_attempts:
				return False

			self._client.put_file(src, remote_path=dst, recursive=os.path.isdir(src))
			success = self.get_checksum(dst) == checksum
			time.sleep(1)

		self._set_permission(owner, group, permissions, dst, max_sessions)
		return True

	def wait_for_remote_task(self, pid, process_name, max_time, sleep_time=60, msg=None):
		"""
		Waits until a process has finished processing on the remote machine, based on PID and process name.
		It will sleep up until the max_time specified, sleeping every x seconds defined by sleep_time. A custom
		message can be specified by msg.
		
		:param string/int pid: PID of process to monitor
		:param string process_name: Name of process to match to PID, for extra verification
		:param float max_time: Maximum amount of time to wait for process to finish
		:param float sleep_time: Time to sleep inbetween checksum
		:param string msg: Custom message to display while waiting
		:return: Whether the process successfully completed in the alloted time or not
		:rtype: boolean
		"""
		if msg is None:
			msg = "Waiting for {pid} to complete"
		msg = msg.format(pid=pid)

		start_time = time.time()
		running = self.check_remote_process(pid, process_name)
		while running:
			if max_time and time.time()-start_time > max_time:
				print("Time has elapsed waiting for process, exiting")
				return False

			print("{msg}... Found [{pid}]".format(msg=msg, pid=pid))
			running = self.check_remote_process(pid, process_name)
			time.sleep(sleep_time)
		return True

	def check_remote_process(self, pid, process_name):
		stdout = self.run(CMD_PS_GREP.format(pid=pid)).stdout
		if isinstance(stdout, list):
			output = "\n".join(stdout)
		return process_name in output

	def kill_process_by_pids(self, pids):
		"""
		Kills a list of processes on the remote machine based on pids. If a list is not passed in
		it will be converted to one. It returns a list of pids that were killed successfully.
		
		:param int/string/list pids: PID(s) to kill on the remote machine
		:return: List of PIDs successfully killed
		:rtype: list
		"""
		if not isinstance(pids, list):
			pids = [pids]

		culled_pids = []
		for pid in pids:
			print("Killing {pid} on remote machine".format(pid=pid))
			if self.run("kill -9 {pid}".format(pid=pid)).success:
				culled_pids.append(pid)
		return culled_pids

	def kill_processes_by_command(self, command):
		"""
		Kills a list of processes on the remote machine based on command being run. 
		It returns a list of pids that were killed successfully.
		
		:param string command: Command to search for on the remote machine
		:return: List of PIDs successfully killed
		:rtype: list
		"""
		culled_pids = []
		processes = self.run("""ps -elf | grep "{command}" | grep -v grep""".format(command=command)).stdout
		for process in processes:
			items = [item for item in process.split(" ") if item]
			pid = items[3]
			print("Killing {pid} on remote machine".format(pid=pid))
			if self.run("kill -9 {pid}".format(pid=pid)).success:
				culled_pids.append(pid)
		return culled_pids

	@staticmethod
	def get_pid_from_ps(lines):
		"""
		Helper function to get pids from ps -elf command
		
		:param list lines: Lines to parse from ps -elf output
		"""
		for line in lines:
			items = [item for item in line.split(" ") if item]
			return items[3]
		return None

	def get_checksum(self, path):
		"""
		Helper function to get checksum of a file on a remote machine
		
		:param string path: Path of file on remote machine
		:return: Checksum of the remote file
		:rtype: string
		"""
		o = self.run("md5sum {path}".format(path=path)).stdout
		checksum = "".join(o).replace(path, "").strip()
		return checksum

	def _create_parent(self, dst, max_sessions=999):
		parent = os.path.dirname(dst)
		if max_sessions == 1:
			with ssh(self._host, self._port, self._user, self._password) as conn:
				try:
					# i, o, e = conn.exec_command("mkdir -p {parent} && [ -d {parent} ]".format(parent=parent))
					i, o, e = conn.exec_command("mkdir -p {parent}".format(parent=parent))
					code = o.channel.recv_exit_status()
					if code == 0:
						return True
					print("Did not create parents: Exit code {code}".format(code=code))
				except Exception as e:
					print("Encountered a problem creating parents: {error}".format(error=str(e)))
			return False
		# return self.run("mkdir -p {parent} && [ -d {parent} ]".format(parent=parent, response_type=RES_SUCCESS))
		return self.run("mkdir -p {parent}".format(parent=parent, response_type=RES_SUCCESS))

	def _set_permission(self, owner, group, permissions, dst, max_sessions):
		if max_sessions == 1:
			with ssh(self._host, self._port, self._user, self._password) as conn:
				if owner and group:
					conn.exec_command("chown {owner}:{group} {path}".format(owner=owner, group=group, path=dst))

				if permissions:
					conn.exec_command("chmod {permissions} {path}".format(permissions=permissions, path=dst))
			return True

		if owner and group:
			self.run("chown {owner}:{group} {path}".format(owner=owner, group=group, path=dst))

		if permissions:
			self.run("chmod {permissions} {path}".format(permissions=permissions, path=dst))
		return True
