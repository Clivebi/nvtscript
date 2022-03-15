if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17323" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 12678 );
	script_name( "aeNovo Database Content Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Restrict access the aeNovo's database file or directory by setting
  file/directory restrictions." );
	script_tag( name: "summary", value: "Due to improper file permission settings on the database directory of
  aeNovo it is possible for a remote attacker to download the product's database file and grab from it
  sensitive information." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/dbase", "/mdb-database", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/aeNovo1.mdb";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!res){
		continue;
	}
	if(ContainsString( res, "Content-Type: application/x-msaccess" ) && ContainsString( res, "Standard Jet DB" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

