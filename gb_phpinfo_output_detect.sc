if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108474" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-19 13:33:54 +0200 (Fri, 19 Oct 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "phpinfo() output Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script tries to identify known files containing an
  output of the phpinfo() PHP function. It will also evaluate previously detected files found
  by the VT 'Web mirroring' (OID: 1.3.6.1.4.1.25623.1.0.10662).

  Note: The reporting takes place in a separate VT 'phpinfo() output Reporting' (OID: 1.3.6.1.4.1.25623.1.0.11229)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
var curr_phpinfo_list;
curr_phpinfo_list = make_list();
func check_and_set_phpinfo( url, host, port ){
	var url, host, port, res;
	res = http_get_cache( item: url, port: port );
	if(!res){
		return;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<title>phpinfo()</title>" )){
		curr_phpinfo_list = make_list( curr_phpinfo_list,
			 url );
		set_kb_item( name: "php/phpinfo/detected", value: TRUE );
		set_kb_item( name: "php/phpinfo/" + host + "/" + port + "/detected", value: TRUE );
		set_kb_item( name: "php/phpinfo/" + host + "/" + port + "/detected_urls", value: url );
		set_kb_item( name: "www/" + host + "/" + port + "/content/phpinfo_script/plain", value: url );
		set_kb_item( name: "www/" + host + "/" + port + "/content/phpinfo_script/reporting", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
		vers = eregmatch( pattern: ">PHP Version ([.0-9A-Za-z]+).*<", string: res );
		if(!isnull( vers[1] )){
			set_kb_item( name: "php/banner/from_scripts/" + host + "/" + port + "/urls", value: url );
			replace_kb_item( name: "php/banner/from_scripts/" + host + "/" + port + "/short_versions/" + url, value: vers[1] );
			vers = eregmatch( pattern: ">PHP Version ([^<]+)<", string: res );
			if(!isnull( vers[1] )){
				replace_kb_item( name: "php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + url, value: vers[1] );
			}
		}
	}
	return;
}
files = make_list( "/phpinfo.php",
	 "/info.php",
	 "/test.php",
	 "/php_info.php",
	 "/index.php",
	 "/i.php",
	 "/test.php?mode=phpinfo" );
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in files {
		url = dir + file;
		check_and_set_phpinfo( url: url, host: host, port: port );
	}
}
kb_phpinfo_scripts = get_kb_list( "www/" + host + "/" + port + "/content/phpinfo_script/plain" );
if(kb_phpinfo_scripts && is_array( kb_phpinfo_scripts )){
	for kb_phpinfo_script in kb_phpinfo_scripts {
		if(curr_phpinfo_list && is_array( curr_phpinfo_list ) && !in_array( search: kb_phpinfo_script, array: curr_phpinfo_list, part_match: FALSE )){
			check_and_set_phpinfo( url: kb_phpinfo_script, host: host, port: port );
		}
	}
}
exit( 0 );

