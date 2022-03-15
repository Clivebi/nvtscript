if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103465" );
	script_bugtraq_id( 52940, 52942 );
	script_cve_id( "CVE-2012-4879", "CVE-2012-3013" );
	script_version( "2020-08-25T06:34:32+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-25 06:34:32 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-04-12 11:29:33 +0200 (Thu, 12 Apr 2012)" );
	script_name( "WAGO I/O SYSTEM 758 Series Insecure Credential Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, "Services/telnet", 23 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52940" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52942" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICSA-12-249-02.pdf" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-097-01.pdf" );
	script_xref( name: "URL", value: "http://www.wago.com/wagoweb/documentation/app_note/a1176/a117600e.pdf" );
	script_tag( name: "summary", value: "The WAGO IPC 758 series are prone to a security-bypass vulnerability
  caused by a set of hard-coded passwords." );
	script_tag( name: "impact", value: "Successful attacks can allow a remote attacker to gain unauthorized
  access to the vulnerable device, using the HTTP or Telnet service." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
credentials = make_list( "root:admin",
	 "admin:admin",
	 "user:user",
	 "user:user00",
	 "guest:guest" );
telnet_ports = telnet_get_ports();
for telnet_port in telnet_ports {
	for credential in credentials {
		soc = open_sock_tcp( telnet_port );
		if(!soc){
			break;
		}
		r = telnet_negotiate( socket: soc );
		if(!ContainsString( r, "WagoIPC1 login" )){
			close( soc );
			break;
		}
		cred = split( buffer: credential, sep: ":", keep: FALSE );
		user = cred[0];
		pass = cred[1];
		send( socket: soc, data: user + "\n" );
		recv = recv( socket: soc, length: 512 );
		if(!ContainsString( recv, "Password" )){
			close( soc );
			continue;
		}
		send( socket: soc, data: pass + "\n" );
		recv = recv( socket: soc, length: 512 );
		if(!ContainsString( recv, "-sh" )){
			close( soc );
			continue;
		}
		report = "It was possible to login using the following credentials: (Username:Password)\n" + credential;
		send( socket: soc, data: "su\n" );
		recv = recv( socket: soc, length: 512 );
		if(ContainsString( recv, "Password" )){
			send( socket: soc, data: "ko2003wa\n" );
			recv = recv( socket: soc, length: 512 );
			if(ContainsString( recv, "this is the super user account" )){
				report += "\nAfter it was possible to login using default credentials it was also possible to \"su\" to the super user account using \"ko2003wa\" as password.";
			}
		}
		close( soc );
		security_message( port: telnet_port, data: report );
	}
}
if(http_is_cgi_scan_disabled()){
	exit( 0 );
}
http_port = http_get_port( default: 80 );
url = "/cgi-bin/ssi.cgi/title.ssi";
req = http_get( item: url, port: http_port );
buf = http_keepalive_send_recv( port: http_port, data: req, bodyonly: FALSE );
if(!buf || !ContainsString( buf, "Wago IO-IPC" )){
	exit( 0 );
}
url = "/security.htm";
req = http_get( item: url, port: http_port );
buf = http_keepalive_send_recv( port: http_port, data: req, bodyonly: FALSE );
if( ContainsString( buf, "Unauthorized" ) ){
	host = http_host_name( port: http_port );
	for credential in credentials {
		userpass64 = base64( str: credential );
		req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n", "\\r\\n" );
		res = http_keepalive_send_recv( port: http_port, data: req );
		if(ContainsString( res, "<title>Configuration side for the web security" ) && ContainsString( res, "Webserver security functions" )){
			httpdesc = "It was possible to login using the following credentials:\nUsername:Password\n" + credential + "\n";
			security_message( port: http_port, data: httpdesc );
			break;
		}
	}
}
else {
	result = "The Wago Web Configuration Page is not protected by any credentials\n";
	security_message( port: http_port, data: result );
}
exit( 0 );

