if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80068" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2006-2351", "CVE-2006-2352", "CVE-2006-2353", "CVE-2006-2354", "CVE-2006-2355", "CVE-2006-2356", "CVE-2006-2357" );
	script_bugtraq_id( 17964 );
	script_xref( name: "OSVDB", value: "25469" );
	script_xref( name: "OSVDB", value: "25470" );
	script_xref( name: "OSVDB", value: "25471" );
	script_xref( name: "OSVDB", value: "25472" );
	script_name( "Ipswitch WhatsUp Professional Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8022 );
	script_mandatory_keys( "Ipswitch/banner" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "summary", value: "The remote web server is affected by multiple flaws.

  Description :

  The remote host appears to be running Ipswitch WhatsUp Professional, which is used to monitor states of
  applications, services and hosts.

  The version of WhatsUp Professional installed on the remote host is prone to multiple issues, including source
  code disclosure and cross-site scripting vulnerabilities." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/433808/30/0/threaded" );
	script_xref( name: "URL", value: "http://www.ipswitch.com/products/whatsup/professional/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8022 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Ipswitch" )){
	exit( 0 );
}
url = "/NmConsole/Login.asp.";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "SOFTWARE\\\\Ipswitch\\\\Network Monitor\\\\WhatsUp" ) && ( ContainsString( res, "<%= app.GetDialogHeader(\"Log In\") %>" ) || egrep( pattern: "<%( +if|@ +LANGUAGE=\"JSCRIPT\")", string: res ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

