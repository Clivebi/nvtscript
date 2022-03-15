if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10385" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2000-1191" );
	script_bugtraq_id( 4366 );
	script_name( "ht://Dig's htsearch reveals web server path" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2000 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securiteam.com/exploits/htDig_reveals_web_server_configuration_paths.html" );
	script_tag( name: "summary", value: "ht://Dig's htsearch CGI can be used to reveal the path location of the its configuration files." );
	script_tag( name: "impact", value: "This allows attacker to gather sensitive information about the remote host." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
	VULN = FALSE;
	url = dir + "/htsearch?config=vt-test&restrict=&exclude=&method=and&format=builtin-long&sort=score&words=";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "ht://Dig error" )){
		if( ContainsString( res, "Unable to read configuration file '" ) ){
			path = eregmatch( pattern: "Unable to read configuration file '(.*)'", string: res );
			if(path){
				banner = "ht://Dig is exposing the local path: " + path[1];
				VULN = TRUE;
			}
		}
		else {
			url = dir + "/htsearch";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			path = eregmatch( pattern: "Unable to read (.*) file '(.*)'", string: res );
			if(path){
				banner = "ht://Dig is exposing the local path: " + path[2];
				VULN = TRUE;
			}
		}
		if(VULN){
			report = http_report_vuln_url( port: port, url: url ) + "\n\n" + banner;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

