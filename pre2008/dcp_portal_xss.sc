if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11446" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2511", "CVE-2004-2512" );
	script_bugtraq_id( 7141, 7144, 11338, 11339, 11340 );
	script_xref( name: "OSVDB", value: "10585" );
	script_xref( name: "OSVDB", value: "10586" );
	script_xref( name: "OSVDB", value: "10587" );
	script_xref( name: "OSVDB", value: "10588" );
	script_xref( name: "OSVDB", value: "10589" );
	script_xref( name: "OSVDB", value: "10590" );
	script_xref( name: "OSVDB", value: "11405" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "DCP-Portal XSS" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2003 k-otik.com & Copyright (C) 2004 David Maciejak" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2004-10/0042.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2004-10/0131.html" );
	script_tag( name: "solution", value: "Upgrade to a newer version when available" );
	script_tag( name: "summary", value: "You are running a version of DCP-Portal which is older or equals to v5.3.2

  This version is vulnerable to:

  - Cross-site scripting flaws in calendar.php script, which may let an
  attacker to execute arbitrary code in the browser of a legitimate user.

  In addition to this, your version may also be vulnerable to:

  - HTML injection flaws, which may let an attacker to inject hostile
  HTML and script code that could permit cookie-based credentials to be stolen
  and other attacks.

  - HTTP response splitting flaw, which may let an attacker to influence
  or misrepresent how web content is served, cached or interpreted." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "50" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/calendar.php?year=2004&month=<script>foo</script>&day=01" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>foo</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

