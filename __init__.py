import time
import os

import paramiko

RES_PID 	= 1
RES_CODE 	= 2
RES_SUCCESS	= 4
RES_STDOUT 	= 8
RES_STDERR	= 16

CMD_PS_GREP	= "ps -p {pid} | grep {pid}"

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

	def connect(self):
		self._client = paramiko.SSHClient()
		self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		if self._load_keys:
			self._client.load_system_host_keys()

		try:
			self._client.connect(
				self._host,
				self._port,
				self._user,
				self._password,
				timeout=self._timeout,
				allow_agent=(self._password is None),
				look_for_keys=(self._password is None))
			if self._scp_client:
				self._scp_client = SCPClient(self._client.get_transport())
			return True
		except Exception as e:
			print("Unable to connect to {host}:{port} as {user}: {error}".format(host=self._host, port=self._port, user=self._user, error=e))
		return False

	def disconnect(self):
		if self._client:
			try:
				self._client.close()
			except Exception:
				pass
		self._client = None

	def run(self, command, redirect="", background=False, max_wait=None, response_type=RES_PID):
		stdout 			= None
		stderr 			= None
		pid				= -1
		exit_code 		= -999
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

				exit_code 	= stdout_obj.channel.recv_exit_status()
				stderr 		= stderr_obj.readlines()
				stdout 		= stdout_obj.readlines()
				if stdout:
					pid 	= stdout[0].strip()
					stdout 	= [l.strip() for l in stdout[1:]]
				if stderr:
					stderr	= [l.strip() for l in stderr]
			except Exception as e:
				print("Encountered a problem while performing SSH ({command}): {error}".format(command=command, error=str(e)))

		out = tuple()
		if response_type & RES_PID:
			out += (pid,)
		if response_type & RES_CODE:
			out += (exit_code,)
		if response_type & RES_SUCCESS:
			out += (exit_code == 0,)
		if response_type & RES_STDOUT:
			out += (stdout,)
		if response_type & RES_STDERR:
			out += (stderr,)
		return out

	def wait_for_remote_task(self, pid, process_name, max_time, sleep_time=60, msg=None):
		if msg is None:
			msg = "Waiting for {pid} to complete"
		msg = msg.format(pid=pid)

		start_time = time.time()
		(stdout,) = self.run(CMD_PS_GREP.format(pid=pid), response_type=RES_STDOUT)
		output = "\n".join(stdout)
		while process_name in output:
			if time.time()-start_time > max_time:
				print("Time has elapsed, exiting")
				return False

			print("{msg}... Found [{pid}]".format(msg=msg, pid=output.split()[0]))
			(stdout,) = self.run(CMD_PS_GREP.format(pid=pid), response_type=RES_STDOUT)
			if isinstance(stdout, list):
				output = "\n".join(stdout)
			time.sleep(sleep_time)
		return True

	def kill_process_by_pids(self, pids):
		if not isinstance(pids, list):
			pids = [pids]

		culled_pids = []
		for pid in pids:
			print("Killing {pid} on remote machine".format(pid=pid))
			(success,) = self.run("kill -9 {pid}".format(pid=pid), response_type=RES_SUCCESS)
			if success:
				culled_pids.append(pid)
		return culled_pids

	def kill_processes_by_command(self, command):
		culled_pids = []
		(processes,) = self.run("""ps -elf | grep "{command}" | grep -v grep""".format(command=command), response_type=RES_STDOUT)
		for process in processes:
			items = [item for item in process.split(" ") if item]
			pid = items[3]
			print("Killing {pid} on remote machine".format(pid=pid))
			(success,) = self.run("kill -9 {pid}".format(pid=pid), response_type=RES_SUCCESS)
			if success:
				culled_pids.append(pid)
		return culled_pids

	@staticmethod
	def get_pid_from_ps(lines):
		for line in lines:
			items = [item for item in line.split(" ") if item]
			return items[3]
		return None

	def get_checksum(self, path):
		(o,) = self.run("md5sum {path}".format(path=path), response_type=RES_STDOUT)
		checksum = "".join(o).replace(path, "").strip()
		return checksum
