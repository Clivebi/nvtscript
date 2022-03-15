if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100552" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-25 19:45:44 +0100 (Thu, 25 Mar 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Interchange Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running Interchange, an open source ecommerce system
  and application server/component application, written in the Perl programming language." );
	script_xref( name: "URL", value: "http://www.icdevgroup.org/i/dev/index" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Interchange Detection";
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/shop", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin/login.html";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "<title>Interchange: Log in to Administration", string: buf, icase: TRUE )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "([0-9.]+[-0-9]*) &copy; [0-9]{4}-[0-9]{4} Interchange Development Group", icase: TRUE );
		if( !isnull( version[1] ) ){
			vers = chomp( version[1] );
			register_host_detail( name: "App", value: NASLString( "cpe:/a:icdevgroup:interchange:", vers ), desc: SCRIPT_DESC );
		}
		else {
			register_host_detail( name: "App", value: NASLString( "cpe:/a:icdevgroup:interchange" ), desc: SCRIPT_DESC );
		}
		set_kb_item( name: NASLString( "www/", port, "/interchange" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "interchange/detected", value: TRUE );
		info = NASLString( "Interbase Version '" );
		info += NASLString( vers );
		info += NASLString( "' was detected on the remote host in the following directory(s):\\n\\n" );
		info += NASLString( install, "\\n" );
		log_message( port: port, data: info );
		exit( 0 );
	}
}
exit( 0 );

