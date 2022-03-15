if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15541" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2207", "CVE-2004-2208", "CVE-2004-2209" );
	script_bugtraq_id( 11424 );
	script_xref( name: "OSVDB", value: "10760" );
	script_xref( name: "OSVDB", value: "10761" );
	script_xref( name: "OSVDB", value: "10762" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "IdealBB multiple flaws" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software." );
	script_tag( name: "summary", value: "The remote version of this IdealBB is vulnerable to multiple
  flaws: SQL injection, cross-site scripting and HTTP response splitting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/idealbb", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/default.asp";
	r = http_get_cache( item: url, port: port );
	if(!r){
		continue;
	}
	if(egrep( pattern: "<title>The Ideal Bulletin Board</title>.*Ideal BB Version: 0\\.1\\.([0-4][^0-9]|5[^.]|5\\.[1-3][^0-9])", string: r )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

