# -*- coding: binary -*-

require 'rex/zip/archive'

module Rex
module Zip

#
# A War is a zip archive containing Java class files
#
class War < Jar

  WEB_XML_HEADER = <<-EOF
<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
EOF

  def initialize(opts)
    super
    app_name = opts[:app_name] || Rex::Text.rand_text_alpha_lower(rand(8)+8)
    #add_file('WEB-INF/', '')

    if opts[:jsp]
      app_name << ".jsp"
      web_xml = build_jsp_web_xml(app_name)

      #add_file(app_name, opts[:jsp])
    else
      web_xml = build_servlet_web_xml(app_name)
    end

    #add_file('WEB-INF/web.xml', web_xml)
  end

  def build_servlet_web_xml(servlet_name)
    web_xml = <<-EOF
#{WEB_XML_HEADER}
<servlet>
<servlet-name>#{servlet_name}</servlet-name>
<servlet-class>metasploit.PayloadServlet</servlet-class>
</servlet>
<servlet-mapping>
<servlet-name>#{servlet_name}</servlet-name>
<url-pattern>/*</url-pattern>
</servlet-mapping>
</web-app>
    EOF

    web_xml
  end

  def build_jsp_web_xml(welcome_filename)
    web_xml = <<-EOF
#{WEB_XML_HEADER}
<welcome-file-list>
<welcome-file>#{welcome_filename}</welcome-file>
</welcome-file-list>
</web-app>
    EOF

    web_xml
  end

end

end
end

