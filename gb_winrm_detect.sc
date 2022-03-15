if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103923" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-03-19 12:39:47 +0100 (Wed, 19 Mar 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "WinRM Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 5985, 5986 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Windows Remote Management (WinRM) is running at this port.

  Windows Remote Management (WinRM) is the Microsoft implementation of
  WS-Management Protocol, a standard Simple Object Access Protocol (SOAP)-based,
  firewall-friendly protocol that allows hardware and operating systems,
  from different vendors, to interoperate." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 5985 );
host = http_host_name( port: port );
vt_strings = get_vt_strings();
req = "POST /wsman HTTP/1.1\r\n" + "Authorization: Negotiate TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAGAHIXAAAADw==\r\n" + "Content-Type: application/soap+xml;charset=UTF-8\r\n" + "User-Agent: Microsoft WinRM Client " + vt_strings["default"] + "\r\n" + "Host: " + host + "\r\n" + "Content-Length: 0\r\n" + "Connection: Close\r\n" + "\r\n";
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "HTTP/1\\.. 401" ) && ContainsString( buf, "Server: Microsoft-HTTPAPI/" ) && ContainsString( buf, "Negotiate TlRMTVNT" )){
	service_register( port: port, ipproto: "tcp", proto: "winrm" );
	log_message( port: port );
}
exit( 0 );

