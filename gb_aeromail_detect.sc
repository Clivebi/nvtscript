if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103204" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "AeroMail Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running AeroMail, a web-based e-mail client written in
  PHP." );
	script_xref( name: "URL", value: "http://www.nicolaas.net/aeromail/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "AeroMail Detection";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/aeromail", "/mail", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "realm=\"AeroMail\"", string: buf, icase: FALSE )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "AeroMail ([0-9.]+)<", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		set_kb_item( name: NASLString( "www/", port, "/AeroMail" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "aeromail/detected", value: TRUE );
		if( vers == "unknown" ){
			register_host_detail( name: "App", value: NASLString( "cpe:/a:aeromail:aeromail" ), desc: SCRIPT_DESC );
		}
		else {
			register_host_detail( name: "App", value: NASLString( "cpe:/a:aeromail:aeromail:", vers ), desc: SCRIPT_DESC );
		}
		info = NASLString( "AeroMail Version '" );
		info += NASLString( vers );
		info += NASLString( "' was detected on the remote host in the following directory(s):\\n\\n" );
		info += NASLString( install, "\\n" );
		log_message( port: port, data: info );
		exit( 0 );
	}
}
exit( 0 );

