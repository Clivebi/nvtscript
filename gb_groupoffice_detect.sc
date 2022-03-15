if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100801" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-14 15:16:41 +0200 (Tue, 14 Sep 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Group-Office Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.group-office.com" );
	script_tag( name: "summary", value: "This host is running Group-Office, a PHP based dual license
  commercial/open source groupware product developed by Dutch company Intermesh." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/go", "/groupware", "/group-office", "/groupoffice", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/about.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "Intermesh" ) && ContainsString( buf, "Group-Office" ) && ContainsString( buf, "Version" )){
		set_kb_item( name: "groupoffice/detected", value: TRUE );
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "Version: ([0-9.]+)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		register_and_report_cpe( app: "Group-Office", ver: vers, concluded: version[0], base: "cpe:/a:group-office:group-office_groupware:", expr: "([0-9.]+)", insloc: install, regPort: port, regService: "www", conclUrl: url );
		exit( 0 );
	}
}
exit( 0 );

