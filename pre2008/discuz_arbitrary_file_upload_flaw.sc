if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19751" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-2614" );
	script_bugtraq_id( 14564 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Discuz! <= 4.0.0 rc4 Arbitrary File Upload Flaw" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0440.html" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software." );
	script_tag( name: "summary", value: "According to its version, the installation of Discuz! on the remote host
  fails to properly check for multiple extensions in uploaded files." );
	script_tag( name: "impact", value: "An attacker may be able to exploit this issue to execute arbitrary commands
  on the remote host subject to the privileges of the web server user id, typically nobody." );
	script_tag( name: "qod_type", value: "remote_banner" );
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
for dir in nasl_make_list_unique( "/discuz", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php" );
	r = http_get_cache( item: url, port: port );
	if(!r){
		continue;
	}
	if(( ContainsString( r, "powered by Discuz!</title>" ) ) && egrep( pattern: "<meta name=\"description\" content=.+Powered by Discuz! Board ([1-3]|4\\.0\\.0RC[0-4])", string: r )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

