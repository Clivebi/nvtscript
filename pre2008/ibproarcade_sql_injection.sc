if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16086" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2004-1430" );
	script_bugtraq_id( 12138 );
	script_name( "IBProArcade index.php SQL Injection" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Ami Chayun" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this appliaction." );
	script_tag( name: "summary", value: "One of the ibProArcade's CGIs, index.php, is vulnerable to
  an SQL injection vulnerability in the 'gameid' parameter." );
	script_tag( name: "impact", value: "An attacker may exploit this flaw to
  execute arbitrary SQL statements against the remote database." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php?act=Arcade&do=stats&gameid=1'" );
	if(http_vuln_check( port: port, url: url, pattern: "SELECT COUNT\\(s_id\\) AS amount FROM ibf_games_scores" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );
