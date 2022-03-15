if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144110" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-06-16 02:30:35 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ZNC Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of ZNC." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 6667 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 6667 );
res = http_get_cache( port: port, item: "/" );
if(concl = eregmatch( string: res, pattern: "(Server\\s*:\\s*ZNC|ZNC - Web Frontend)[^\r\n]+", icase: TRUE )){
	version = "unknown";
	concluded = chomp( concl[0] );
	set_kb_item( name: "znc/detected", value: TRUE );
	set_kb_item( name: "znc/http/detected", value: TRUE );
	set_kb_item( name: "znc/http/port", value: port );
	set_kb_item( name: "znc/http/" + port + "/detected", value: TRUE );
	vers = eregmatch( pattern: "Server\\s*:\\s*ZNC( \\-)? ([0-9.]+)[^ ]* - http", string: res );
	if(!isnull( vers[2] )){
		version = vers[2];
		concluded = vers[0];
	}
	if(version == "unknown"){
		vers = eregmatch( pattern: ">ZNC( \\-)? ([0-9.]+)[^ ]* - <", string: res );
		if(!isnull( vers[2] )){
			version = vers[2];
			concluded = vers[0];
		}
	}
	set_kb_item( name: "znc/http/" + port + "/concluded", value: concluded );
	set_kb_item( name: "znc/http/" + port + "/version", value: version );
}
exit( 0 );

