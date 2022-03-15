if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12113" );
	script_version( "2021-09-28T10:33:08+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 10:33:08 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-0422" );
	script_name( "Private IP address Leaked using the PROPFIND method" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Sword & Shield Enterprise Security, Inc." );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "keys/is_private_addr", "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://support.microsoft.com/default.aspx?scid=KB%3BEN-US%3BQ218180&ID=KB%3BEN-US%3BQ218180" );
	script_xref( name: "URL", value: "http://www.nextgenss.com/papers/iisrconfig.pdf" );
	script_tag( name: "solution", value: "See the references for an update / more information." );
	script_tag( name: "summary", value: "The remote web server leaks a private IP address through the
  WebDAV interface. If this web server is behind a Network Address Translation (NAT) firewall or
  proxy server, then the internal IP addressing scheme has been leaked.

  This is typical of IIS 5.0 installations that are not configured properly." );
	script_tag( name: "solution_type", value: "Mitigation" );
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
host = http_host_name( port: port );
req = "PROPFIND / HTTP/1.0\r\n" + "Host: " + host + "\r\n" + "Content-Length: 0\r\n\r\n";
buf = http_keepalive_send_recv( port: port, data: req );
private_ip = eregmatch( pattern: "([^12]10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3}|192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3})", string: buf );
if(!isnull( private_ip ) && !IsMatchRegexp( private_ip, "Oracle.*/10\\." )){
	report = "This web server leaks the following private IP address: " + private_ip[0] + "\n\n";
	report += http_report_vuln_url( port: port, url: "/" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

