#!/usr/bin/env python3


#Author: B31212Y

# My hackable attempt to automate the process of Detecting Malicious Kernel Process Thread (DMKPT) based on the blog post.

#Source: https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/

#Tip: Make sure you run this code with root privilege access else you wont be able to read maps file.	


import subprocess

import os,time


yellow = "\033[33;1m"
red = "\033[31;1m"
green = "\033[32;1m"
purple = "\033[35;1m"
reset = "\033[m"



def banner():


        print(purple +'''

		 *******         ****     ****       **   **       *******        **********
		/**////**       /**/**   **/**      /**  **       /**////**      /////**/// 
		/**    /**      /**//** ** /**      /** **        /**   /**          /**    
		/**    /**      /** //***  /**      /****         /*******           /**    
		/**    /**      /**  //*   /**      /**/**        /**////            /**    
		/**    **       /**   /    /**      /**//**       /**                /**    
		/*******        /**        /**      /** //**      /**                /**    
		///////         //         //       //   //       //                 //     
		
		''' + reset)		


def get_all_proc():

	print(yellow + "[+] Retrieving all process of the system" + reset)

	proc_pid = subprocess.check_output(["ps", "-eo", "pid,cmd,user"])

	proc_pid_newline = proc_pid.split(b"\n")
	
	print(yellow + "[*] Checking for existence of pid.txt file" + reset)
		
	if os.path.isfile('pid.txt'):
		
		print(yellow + "[+] pid.txt file exists and deleting it\n" + reset)
		os.system("rm -f pid.txt")
	else:
		print(yellow + "[*] pid.txt file does not exist" + reset)		
	proc_file = open("pid.txt" , "x")

	for proc in proc_pid_newline:

		# Checking for any process which starts with [ , always check the pid is running in which user context
		# I have currently not done this check if you run this through ubuntu you might get avahi-daemon as malicious process

		if b'[' in proc:
			proc_dec = str(proc.decode())
			proc_split = proc_dec.split()		

			#Getting the feild 0 which is the PID of process
			proc_pid = proc_split[0]
			proc_cmd = proc_split[1]
			proc_usr = proc_split[2]
			
			#uncomment below line which will print pid,cmd,user
		
			#print(proc_pid,proc_cmd,proc_usr)

			#Writing all the process to a file pid.txt

			proc_file.write(proc_pid + "\n")

	print(green + "[+] Writing all the pid in pid.txt file\n" + reset)

	proc_file.close()


def pid_read():
	file_pid = open('pid.txt', 'r')

	for pid_val in file_pid.read().splitlines():

	# I was actually trying to check the size of file and then validate it
	# unfortunately this does not seem to work.	
	#	print("/proc/" + pid_val + "/maps")
	#	if os.stat("/proc/" + pid_val + "/maps").st_size == 0:
	#		print("Safe")
	#	else:
	#		print("DANGER")
	# I ended with reading those files and checking for any values inside it, real kernel threads wont have any data available

	
		f_pid = "/proc/" + pid_val + "/maps"
		pid_open = open(f_pid, 'r')
				
		for val in pid_open.read().splitlines():

			if val:
				print(red + "File: " +f_pid + reset)
				print(purple +"-"*50 + reset)
				print( red + "Malicious process running with pid: " + pid_val + reset)
				print(yellow + "\n[+] Generating SHA1 hash from /proc/" + pid_val + "/exe\n" + reset)
				pid_path_exe = "/proc/" + pid_val + "/exe"
				exe_hash = subprocess.check_output(['sha1sum', pid_path_exe])
				print(red + exe_hash.decode() + reset)
				print(yellow + "\nCheck this hash in any of the known Malware DB" + reset)
				print(purple + "-"*50 + reset)
				break
		

		
		
if __name__ == "__main__":

#	print("\n")
	banner()
	
#	print("\n")
	get_all_proc()

	time.sleep(1)

	pid_read()

	print(yellow + "[+] Deleting pid.txt file" + reset)		
	os.system("rm -f pid.txt")
	print(green + "[+] Cleanup completed!" + reset)
