if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15717" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2245" );
	script_bugtraq_id( 11587 );
	script_xref( name: "OSVDB", value: "11318" );
	script_xref( name: "OSVDB", value: "11319" );
	script_xref( name: "OSVDB", value: "11320" );
	script_xref( name: "OSVDB", value: "11624" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Goollery Multiple XSS" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to Goollery 0.04b or newer." );
	script_tag( name: "summary", value: "Goollery, a GMail based photo gallery written in PHP,
  is installed on this remote host.

  According to it's version number, this host is vulnerable to multiple
  cross-site-scripting (XSS) attacks eg. through the 'viewpic.php'
  script." );
	script_tag( name: "impact", value: "An attacker, exploiting these flaws, would need to be able to
  coerce a user to browse a malicious URI. Upon successful exploitation, the attacker would be able
  to run code within the web-browser in the security context of the remote server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/goollery", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/viewpic.php?id=7&conversation_id=<script>foo</script>&btopage=0" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>foo</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

