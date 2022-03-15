if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15557" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2180", "CVE-2004-2181" );
	script_bugtraq_id( 11429 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WowBB <= 1.61 multiple flaws" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "According to its version, the remote installation of WowBB is 1.61 or
  older. Such versions are vulnerable to cross-site scripting and SQL
  injection attacks." );
	script_tag( name: "impact", value: "A malicious user can steal users' cookies,
  including authentication cookies, and manipulate SQL queries." );
	script_xref( name: "URL", value: "http://www.maxpatrol.com/advdetails.asp?id=7" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
for dir in nasl_make_list_unique( "/forum", "/forums", "/board", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	r = http_get_cache( item: url, port: port );
	if(!r){
		continue;
	}
	if(egrep( pattern: "WowBB Forums</TITLE>.*TITLE=.WowBB Forum Software.*>WowBB (0\\..*|1\\.([0-5][0-9]|60|61))</A>", string: r )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

