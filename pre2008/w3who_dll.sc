if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15910" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2004-1133", "CVE-2004-1134" );
	script_bugtraq_id( 11820 );
	script_name( "w3who.dll overflow and XSS" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (C) 2004 Nicolas Gregoire <ngregoire@exaprobe.com>" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "IIS/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Delete this file." );
	script_tag( name: "summary", value: "The Windows 2000 Resource Kit ships with a DLL that displays
  the browser client context. It lists security identifiers, privileges and $ENV variables.

  The scanner has determined that this file is installed on the remote host." );
	script_tag( name: "impact", value: "The w3who.dll ISAPI may allow an attacker to execute arbitrary
  commands on this host, through a buffer overflow, or to mount XSS attacks." );
	script_xref( name: "URL", value: "http://www.exaprobe.com/labs/advisories/esa-2004-1206.html" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
baner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "IIS" )){
	exit( 0 );
}
url = "/scripts/w3who.dll";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Access Token" )){
	report = http_report_vuln_url( port: port, url: url );
	if(safe_checks()){
		security_message( port: port, data: report );
		exit( 0 );
	}
	useragent = http_get_user_agent();
	req = NASLString( "GET /scripts/w3who.dll?", crap( 600 ), " HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", "User-Agent: ", useragent, "\\r\\n" );
	r = http_send_recv( port: port, data: req );
	if(ContainsString( r, "HTTP/1.1 500 Server Error" ) && ContainsString( r, "<html><head><title>Error</title>" )){
		security_message( port: port, data: report );
	}
}
exit( 99 );

