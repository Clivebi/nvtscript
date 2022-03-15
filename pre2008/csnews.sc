if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11726" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4994 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0923" );
	script_name( "CSNews.cgi vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 John Lampe" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_mandatory_keys( "IIS/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Remove it from the cgi-bin or scripts directory." );
	script_tag( name: "summary", value: "The CSNews.cgi exists on this webserver. Some versions of this file
  are vulnerable to remote exploit." );
	script_tag( name: "impact", value: "An attacker may make use of this file to gain access to
  confidential data or escalate their privileges on the Web server." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Microsoft/IIS" )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/csNews.cgi";
	if(http_is_cgi_installed_ka( item: url, port: port )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

