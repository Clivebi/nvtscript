if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16059" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1419" );
	script_bugtraq_id( 12103 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Zeroboard flaws" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://marc.info/?l=bugtraq&m=110391024404947&w=2" );
	script_tag( name: "solution", value: "Upgrade to Zeroboard 4.1pl5 or later." );
	script_tag( name: "summary", value: "The remote host runs Zeroboard, a web BBS application popular in
  Korea which is prone to arbitrary PHP code execution and cross-site scripting attacks." );
	script_tag( name: "insight", value: "The remote version of this software is vulnerable to cross-site
  scripting and remote script injection due to a lack of sanitization of user-supplied data." );
	script_tag( name: "impact", value: "Successful exploitation of this issue may allow an attacker to execute
  arbitrary code on the remote host or to use it to perform an attack against third-party users." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
for dir in nasl_make_list_unique( "/bbs", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/check_user_id.php?user_id=<script>foo</script>" );
	req = http_get( item: url, port: port );
	r = http_keepalive_send_recv( port: port, data: req );
	if(!r){
		continue;
	}
	if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && ContainsString( r, "ZEROBOARD.COM" ) && ContainsString( r, "<script>foo</script>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

