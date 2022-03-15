if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103158" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-05-03 13:15:04 +0200 (Tue, 03 May 2011)" );
	script_name( "LDAP Account Manager Detection" );
	script_tag( name: "summary", value: "This host is running LDAP Account Manager
, a webfrontend for managing entries (e.g. users, groups, DHCP settings) stored
  in an LDAP directory." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8181 );
	script_mandatory_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8181 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/ldap", "/ldap-account-manager", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/templates/login.php" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "<title>LDAP Account Manager</title>" ) && ContainsString( buf, "LAM configuration" )){
		lamvers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "LDAP Account Manager - ([0-9.]+)", icase: TRUE );
		if(!isnull( version[1] )){
			lamvers = chomp( version[1] );
		}
		set_kb_item( name: "www/" + port + "/ldap_account_manager", value: NASLString( lamvers, " under ", install ) );
		set_kb_item( name: "ldap_account_manager/installed", value: TRUE );
		cpe = build_cpe( value: lamvers, exp: "^([0-9.]+)", base: "cpe:/a:ldap_account_manager:ldap_account_manager:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:ldap_account_manager:ldap_account_manager";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "LDAP Account Manager", version: lamvers, install: install, cpe: cpe, concluded: lamvers ), port: port );
		exit( 0 );
	}
}
exit( 0 );

