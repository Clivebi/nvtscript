if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11230" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_bugtraq_id( 4785 );
	script_name( "Stronghold Swish" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Randy Matz" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "An information disclosure vulnerability was reported in a
  sample script provided with Red Hat's Stronghold web server." );
	script_tag( name: "impact", value: "A remote user can determine the web root directory path.

  A remote user can send a request to the Stronghold sample script
  swish to cause the script to reveal the full path to the webroot directory.

  Apparently, swish may also display system-specific information in the
  HTML returned by the script" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
	url = dir + "/search";
	if(http_is_cgi_installed_ka( port: port, item: url )){
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(egrep( pattern: "sourcedir value=./.*stronghold.*", string: res ) || egrep( pattern: ".*sourcedir value=?/.*stronghold.*", string: res )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

