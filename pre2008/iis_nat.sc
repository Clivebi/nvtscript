if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10759" );
	script_version( "2021-09-28T10:33:08+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 10:33:08 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1499 );
	script_cve_id( "CVE-2000-0649" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_name( "Private IP address leaked in HTTP headers" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Alert4Web.com, 2003 Westpoint Ltd" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "keys/is_private_addr", "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/218180" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/1499/" );
	script_xref( name: "URL", value: "http://foofus.net/?p=758" );
	script_tag( name: "summary", value: "This web server leaks a private IP address through its HTTP
  headers." );
	script_tag( name: "impact", value: "This may expose internal IP addresses that are usually hidden or
  masked behind a Network Address Translation (NAT) Firewall or proxy server." );
	script_tag( name: "insight", value: "There is a known issue with IIS 4.0 doing this in its default
  configuration.

  Furthermore Microsoft Exchange CAS and OWA as well as other webservers or load balancers might be
  also affected." );
	script_tag( name: "solution", value: "See the references for possible workarounds and updates." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("network_func.inc.sc");
if(is_private_addr()){
	exit( 0 );
}
port = http_get_port( default: 80 );
useragent = http_get_user_agent();
for dir in make_list( "/",
	 "/images",
	 "/Autodiscover",
	 "/Autodiscover/Autodiscover.xml",
	 "/Microsoft-Server-ActiveSync",
	 "/Microsoft-Server-ActiveSync/default.css",
	 "/ECP",
	 "/EWS",
	 "/EWS/Exchange.asmx",
	 "/Exchange",
	 "/OWA",
	 "/Microsoft-Server-ActiveSync/default.eas",
	 "/Rpc",
	 "/EWS/Services.wsdl",
	 "/ecp",
	 "/OAB",
	 "/aspnet_client",
	 "/PowerShell" ) {
	req = "GET " + dir + " HTTP/1.0\r\n" + "User-Agent: " + useragent + "\r\n" + "\r\n";
	buf = http_keepalive_send_recv( port: port, data: req, headersonly: TRUE );
	private_ip = eregmatch( pattern: "([^12]10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3}|192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3})", string: buf );
	if(!isnull( private_ip ) && !egrep( pattern: "Oracle.*/10\\.", string: buf )){
		report = "This web server leaks the following private IP address : " + private_ip[0] + "\n\n";
		report += http_report_vuln_url( port: port, url: dir );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

