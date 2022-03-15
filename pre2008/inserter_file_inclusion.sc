if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18149" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "inserter.cgi File Inclusion and Command Execution Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Delete this file" );
	script_tag( name: "summary", value: "The remote web server contains the 'inserter' CGI.

 The inserter.cgi contains a vulnerability that allows remote attackers to cause
 the CGI to execute arbitrary commands with the privileges of the web server
 by supplying it with a piped instruction or to include arbitrary files by
 providing an absolute path to the location of the file." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
files = traversal_files();
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for pattern in keys( files ) {
		file = files[pattern];
		req = http_get( item: dir + "/inserter.cgi?/" + file, port: port );
		r = http_keepalive_send_recv( port: port, data: req );
		if(r == NULL){
			exit( 0 );
		}
		if(egrep( pattern: pattern, string: r )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

