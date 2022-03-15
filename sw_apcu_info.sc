if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111025" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-07-27 16:00:00 +0200 (Mon, 27 Jul 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "APC / APCu INFO page accessible" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Delete them or restrict access to the listened files." );
	script_tag( name: "summary", value: "The APC / APCu INFO page is providing internal information
  about the system." );
	script_tag( name: "impact", value: "Some of the information that could be gathered from this file
  includes: The running APC/APCu version, the PHP version, the webserver version." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
var isvuln, report;
func check_and_set_phpinfo( url, host, port ){
	var url, host, port, res;
	res = http_get_cache( item: url, port: port );
	if(!res){
		return;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<title>APC INFO" ) || ContainsString( res, "<title>APCu INFO" ) )){
		isvuln = TRUE;
		report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		vers = eregmatch( pattern: ">PHP Version</td><td>([.0-9A-Za-z]+).*</td></tr>", string: res );
		if(!isnull( vers[1] )){
			set_kb_item( name: "php/banner/from_scripts/" + host + "/" + port + "/urls", value: url );
			replace_kb_item( name: "php/banner/from_scripts/" + host + "/" + port + "/short_versions/" + url, value: vers[1] );
			vers = eregmatch( pattern: ">PHP Version</td><td>([^<]+)</td></tr>", string: res );
			if(!isnull( vers[1] )){
				replace_kb_item( name: "php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + url, value: vers[1] );
			}
		}
	}
	return;
}
report = "The following files are providing a APC / APCu INFO page which disclose potentially sensitive information:\n";
files = make_list( "/index.php",
	 "/apc.php",
	 "/apcu.php",
	 "/apcinfo.php" );
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
for dir in nasl_make_list_unique( "/", "/apc", "/cache", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in files {
		url = dir + file;
		check_and_set_phpinfo( url: url, host: host, port: port );
	}
}
if(isvuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

