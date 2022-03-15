if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805471" );
	script_version( "2021-09-22T11:23:09+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 11:23:09 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-03-20 11:52:44 +0530 (Fri, 20 Mar 2015)" );
	script_name( "ManageEngine OpManager Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of ManageEngine OpManager.

  The script sends a connection request to the server and attempts to detect ManageEngine OpManager
  and to extract its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8060 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.manageengine.com/network-monitoring/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8060 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/LoginPage.do";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "ManageEngine" ) && ContainsString( buf, "OpManager" ) && ContainsString( buf, "opmLoginFieldHolder" )){
		version = "unknown";
		set_kb_item( name: "manageengine/opmanager/detected", value: TRUE );
		set_kb_item( name: "manageengine/opmanager/http/detected", value: TRUE );
		set_kb_item( name: "manageengine/opmanager/http/port", value: port );
		set_kb_item( name: "manageengine/opmanager/http/" + port + "/location", value: install );
		vers = eregmatch( pattern: "/cachestart/([0-9]+)/cacheend/", string: buf );
		if(!isnull( vers[1] )){
			set_kb_item( name: "manageengine/opmanager/http/" + port + "/concluded", value: vers[0] );
			version = vers[1];
		}
		set_kb_item( name: "manageengine/opmanager/http/" + port + "/version", value: version );
		exit( 0 );
	}
}
exit( 0 );

