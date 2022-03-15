if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800109" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)" );
	script_name( "PHP Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "gb_phpinfo_output_detect.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "sw_apcu_info.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of PHP." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
checkFiles = make_list();
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	checkFiles = make_list( checkFiles,
		 dir + "/",
		 dir + "/index.php" );
}
phpFilesList = http_get_kb_file_extensions( port: port, host: host, ext: "php" );
if(phpFilesList && is_array( phpFilesList )){
	count = 0;
	for phpFile in phpFilesList {
		count++;
		checkFiles = nasl_make_list_unique( checkFiles, phpFile );
		if(count >= 10){
			break;
		}
	}
}
var version,phpSessId;
for checkFile in checkFiles {
	banner = http_get_remote_headers( port: port, file: checkFile );
	if(ContainsString( banner, "PHP" )){
		phpInfo = egrep( pattern: "Server.*PHP.*", string: banner, icase: FALSE );
		if(!phpInfo){
			phpInfo = egrep( pattern: "X.Powered.By.*PHP.*", string: banner, icase: FALSE );
		}
		if(ContainsString( banner, "PHPSESSID" )){
			phpSessId = TRUE;
		}
		version = ereg_replace( pattern: ".*PHP/([.0-9A-Za-z]*).*", string: phpInfo, replace: "\\1" );
		if(!isnull( version ) && version != ""){
			break;
		}
	}
}
if(isnull( version ) || version == ""){
	phpscriptsUrls = get_kb_list( "php/banner/from_scripts/" + host + "/" + port + "/urls" );
	if(phpscriptsUrls && is_array( phpscriptsUrls )){
		for phpscriptsUrl in phpscriptsUrls {
			_version = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/short_versions/" + phpscriptsUrl );
			_phpInfo = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + phpscriptsUrl );
			if(_version && IsMatchRegexp( _version, "[0-9.]+" )){
				version = _version;
				phpInfo = _phpInfo;
				conclUrl = http_report_vuln_url( port: port, url: phpscriptsUrl, url_only: TRUE ) + " (phpinfo()/ACP(u) output)";
				break;
			}
		}
	}
}
if(version || phpSessId){
	location = port + "/tcp";
	if(!phpInfo && phpSessId){
		phpInfo = "PHPSESSID Session-Cookie";
	}
	if(!version){
		version = "unknown";
	}
	set_kb_item( name: "www/" + port + "/PHP", value: version );
	set_kb_item( name: "php/detected", value: TRUE );
	replace_kb_item( name: "www/" + port + "/can_host_php", value: "yes" );
	cpe = build_cpe( value: version, exp: "^([0-9.A-Za-z]+)", base: "cpe:/a:php:php:" );
	if(!cpe){
		cpe = "cpe:/a:php:php";
	}
	register_product( cpe: cpe, location: location, port: port, service: "www" );
	log_message( data: build_detection_report( app: "PHP", version: version, install: location, cpe: cpe, concludedUrl: conclUrl, concluded: phpInfo ), port: port );
}
exit( 0 );

