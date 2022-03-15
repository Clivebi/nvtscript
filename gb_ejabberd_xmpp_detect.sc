if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100486" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "ejabberd Detection (XMPP)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "xmpp_detect.sc" );
	script_require_ports( "Services/xmpp", 5269 );
	script_tag( name: "summary", value: "XMPP based detection of ejabberd." );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(!port = service_get_port( default: 5269, proto: "xmpp-server" )){
	exit( 0 );
}
server = get_kb_item( "xmpp/" + port + "/server" );
if(ContainsString( server, "ejabberd" )){
	version = "unknown";
	set_kb_item( name: "ejabberd/detected", value: TRUE );
	set_kb_item( name: "ejabberd/xmpp/port", value: port );
	vers = get_kb_item( NASLString( "xmpp/", port, "/version" ) );
	if(!isnull( vers )){
		version = vers;
		set_kb_item( name: "ejabberd/xmpp/" + port + "/concluded", value: vers );
	}
	set_kb_item( name: "ejabberd/xmpp/" + port + "/version", value: version );
}
exit( 0 );

