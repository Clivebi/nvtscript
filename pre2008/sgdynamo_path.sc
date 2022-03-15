if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11954" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Sgdynamo 'sgdynamo.exe' Physical Path Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Scott Shebby" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The CGI 'sgdynamo.exe' can be tricked into giving the physical path to the
  remote web root." );
	script_tag( name: "impact", value: "This information may be useful to an attacker who can use it to make better
  attacks against the remote server." );
	script_tag( name: "qod", value: "50" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/sgdynamo.exe?HTNAME=sgdynamo.exe";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	path = egrep( pattern: "[aA-zZ]:\\\\.*sgdynamo\\.exe", string: res );
	if(path){
		path = ereg_replace( string: path, pattern: ".*([aA-zZ]:\\\\.*sgdynamo\\.exe).*", replace: "\\1" );
		report = "It is possible to obtain the physical path to the remote website by sending the following request :" + egrep( pattern: "^GET /", string: req ) + "We determined that the remote web path is : '" + path + "'";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

