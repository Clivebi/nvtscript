if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100382" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "PhpShop Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running PhpShop, a PHP-powered shopping cart application." );
	script_xref( name: "URL", value: "http://www.phpshop.org/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "PhpShop Detection";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/shop", "/phpshop", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "Powered by <a [^>]+>phpShop", string: buf, icase: TRUE )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "Powered by <a [^>]+>phpShop</a> ([0-9.]+)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
			if(version_is_equal( version: vers, test_version: "0.8.0" )){
				url = NASLString( dir, "/README.txt" );
				req = http_get( item: url, port: port );
				buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				if(buf){
					version = eregmatch( string: buf, pattern: "phpShop version ([0-9.]+)" );
					if(!isnull( version[1] ) && version[1] != vers){
						vers = version[1];
					}
				}
			}
		}
		tmp_version = NASLString( vers, " under ", install );
		set_kb_item( name: NASLString( "www/", port, "/phpshop" ), value: tmp_version );
		set_kb_item( name: "phpshop/detected", value: TRUE );
		cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+)", base: "cpe:/a:edikon:phpshop:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		info = NASLString( "PhpShop Version '" );
		info += NASLString( vers );
		info += NASLString( "' was detected on the remote host in the following directory(s):\\n\\n" );
		info += NASLString( install, "\\n" );
		log_message( port: port, data: info );
		exit( 0 );
	}
}
exit( 0 );

