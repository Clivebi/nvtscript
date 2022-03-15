if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10797" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "ColdFusion Debug Mode" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Felix Huber" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Enter a IP (e.g. 127.0.0.1) in the Debug Settings
  within the ColdFusion Admin." );
	script_tag( name: "summary", value: "It is possible to see the ColdFusion Debug Information
  by appending ?Mode=debug at the end of the request (like GET /index.cfm?Mode=debug).

  4.5 and 5.0 are definitely concerned (probably in
  addition older versions).

  The Debug Information usually contain sensitive data such
  as Template Path or Server Version." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
files = make_list( "/",
	 "/index.cfm",
	 "/index.cfml",
	 "/home.cfm",
	 "/home.cfml",
	 "/default.cfml",
	 "/default.cfm" );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in files {
		url = dir + file + "?Mode=debug";
		if(http_vuln_check( port: port, url: url, pattern: "CF_TEMPLATE_PATH" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

