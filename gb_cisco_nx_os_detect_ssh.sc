if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103817" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-10-21 11:24:09 +0200 (Mon, 21 Oct 2013)" );
	script_name( "Cisco NX-OS Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_show_version.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "cisco/show_version" );
	script_tag( name: "summary", value: "This script performs SSH based detection of Cisco NX-OS." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
show_ver = get_kb_item( "cisco/show_version" );
if(!ContainsString( show_ver, "Cisco Nexus Operating System (NX-OS) Software" )){
	exit( 0 );
}
set_kb_item( name: "cisco/nx_os/detected", value: TRUE );
vers = "unknown";
model = "unknown";
device = "unknown";
source = "ssh";
version = eregmatch( pattern: "system:\\s+version\\s+([0-9a-zA-Z\\.\\(\\)]+)[^\\s\\r\\n]*", string: show_ver );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "cisco/nx_os/" + source + "/version", value: vers );
}
if( ContainsString( show_ver, "MDS" ) ) {
	device = "MDS";
}
else {
	device = "Nexus";
}
lines = split( buffer: show_ver, keep: FALSE );
for line in lines {
	if(!ContainsString( line, "Chassis" )){
		continue;
	}
	mod = eregmatch( pattern: "cisco (Unknown|Nexus|MDS)\\s(.*)\\sChassis", string: line, icase: TRUE );
	break;
}
if(!isnull( mod[2] )){
	model = mod[2];
}
set_kb_item( name: "cisco/nx_os/" + source + "/device", value: device );
set_kb_item( name: "cisco/nx_os/" + source + "/model", value: model );
exit( 0 );

