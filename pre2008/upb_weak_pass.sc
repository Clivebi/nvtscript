if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19497" );
	script_version( "2021-05-17T09:15:04+0000" );
	script_tag( name: "last_modification", value: "2021-05-17 09:15:04 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-2005", "CVE-2005-2030" );
	script_bugtraq_id( 13975 );
	script_xref( name: "OSVDB", value: "17374" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Ultimate PHP Board users.dat Information Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/archive/1/402506" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/archive/1/402461" );
	script_tag( name: "summary", value: "The remote host is running Ultimate PHP Board (UPB).

  The remote version of this software is prone to a weak password encryption
  vulnerability and may store the users.dat file under the web document root
  with insufficient access control." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/db/users.dat";
	if(http_vuln_check( port: port, url: url, pattern: "<~>20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]<~>[0-9]+$" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ver = egrep( pattern: "Powered by UPB Version : 1\\.([0-8]|9\\.[0-6])", string: res )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "None" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

