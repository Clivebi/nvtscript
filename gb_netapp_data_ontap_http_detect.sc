if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140348" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-09-05 08:44:27 +0700 (Tue, 05 Sep 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NetApp Data ONTAP Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of NetApp Data ONTAP.

This script performs HTTP based detection of NetApp Data ONTAP devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.netapp.com/us/products/data-management-software/ontap.aspx" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if( egrep( pattern: "(NetApp|Data ONTAP)/", string: banner ) ){
	detected = TRUE;
}
else {
	buf = http_get_cache( item: "/sysmgr/SysMgr.html", port: port );
	if(buf && ContainsString( buf, "<meta sm_build_version" ) && ContainsString( buf, "sysmgr/sysmgr.nocache.js" )){
		detected = TRUE;
	}
}
if(detected){
	set_kb_item( name: "netapp_data_ontap/detected", value: TRUE );
	set_kb_item( name: "netapp_data_ontap/http/detected", value: TRUE );
	set_kb_item( name: "netapp_data_ontap/http/port", value: port );
	vers = eregmatch( pattern: "Server: (NetApp|Data ONTAP)//?([0-9P.]+)", string: banner );
	if( !isnull( vers[2] ) ){
		version = vers[2];
		set_kb_item( name: "netapp_data_ontap/http/" + port + "/version", value: version );
		set_kb_item( name: "netapp_data_ontap/http/" + port + "/concluded", value: vers[0] );
	}
	else {
		set_kb_item( name: "netapp_data_ontap/http/" + port + "/concluded", value: "NetApp OnCommand System Manager Interface" );
	}
}
exit( 0 );

