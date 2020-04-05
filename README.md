# DMKPT - Detecting Malicious Kernel Process Thread

My hackable attempt to automate the process of Detecting Malicious Kernel Process Thread (DMKPT) based on the blog post (https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/).

Steps to mimic malicious kernel process:

Type these things in terminal 

#export PATH=.:$PATH<br />
#cp /usr/bin/yes /tmp/[AJ]<br />
#cd /tmp<br />
#"[AJ]"<br />

And atlast run the DMKPT.py file

*Yes is a utility which output's a string repeatedly until killed, Look for man page of yes.<br />
**Make sure you run this with root user<br />

NOTE: The scripts only identifies malicious process which masquerades as a kernenel process thread.

This is how the output looks like:

![Screenshot of the output](https://github.com/AkiJos/DMKPT/blob/master/DMKPT.png)
