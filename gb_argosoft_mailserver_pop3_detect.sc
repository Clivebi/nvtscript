if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113667" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-03 11:19:00 +0100 (Fri, 03 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ArgoSoft Mail Server Detection (POP3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "popserver_detect.sc" );
	script_mandatory_keys( "pop3/argosoft/mailserver/detected" );
	script_tag( name: "summary", value: "Checks whether ArgoSoft Mail Server is present on
  the target system and if so, tries to figure out the installed version." );
	exit( 0 );
}
require("host_details.inc.sc");
require("pop3_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = pop3_get_port( default: 110 );
buf = pop3_get_banner( port: port );
if(IsMatchRegexp( buf, "ArGoSoft Mail Server" )){
	set_kb_item( name: "argosoft/mailserver/detected", value: TRUE );
	set_kb_item( name: "argosoft/mailserver/pop3/detected", value: TRUE );
	set_kb_item( name: "argosoft/mailserver/pop3/port", value: port );
	version = "unknown";
	ver = eregmatch( string: buf, pattern: "ArGoSoft Mail Server[^\n]*(\\(([0-9.]+)\\)|v\\.([0-9.]+))", icase: TRUE );
	if( !isnull( ver[2] ) ){
		version = ver[2];
	}
	else {
		if(!isnull( ver[3] )){
			version = ver[3];
		}
	}
	if(version != "unknown"){
		set_kb_item( name: "argosoft/mailserver/pop3/" + port + "/version", value: version );
		set_kb_item( name: "argosoft/mailserver/pop3/" + port + "/concluded", value: ver[0] );
	}
}
exit( 0 );

