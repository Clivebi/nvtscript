if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105328" );
	script_version( "2019-06-11T14:05:30+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-06-11 14:05:30 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "creation_date", value: "2015-08-21 14:51:09 +0200 (Fri, 21 Aug 2015)" );
	script_name( "pfSense Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "pfsense/uname" );
	script_tag( name: "summary", value: "This script performs SSH based detection of pfSense." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
uname = get_kb_item( "pfsense/uname" );
if(!uname || !ContainsString( uname, "pfSense" )){
	exit( 0 );
}
port = get_kb_item( "pfsense/ssh/port" );
set_kb_item( name: "pfsense/installed", value: TRUE );
set_kb_item( name: "pfsense/ssh/installed", value: TRUE );
vers = "unknown";
version = eregmatch( pattern: "Welcome to pfSense ([^-]+)-RELEASE-?(p[0-9]+)?", string: uname );
if(!isnull( version[1] )){
	set_kb_item( name: "pfsense/ssh/" + port + "/version", value: version[1] );
	set_kb_item( name: "pfsense/ssh/" + port + "/concluded", value: uname );
	if(!isnull( version[2] )){
		set_kb_item( name: "pfsense/ssh/" + port + "/patch", value: version[2] );
	}
}
exit( 0 );

