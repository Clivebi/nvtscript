if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105655" );
	script_version( "$Revision: 10896 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-06 16:48:59 +0200 (Mon, 06 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cisco IOS Software Version Detection (ssh)" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_tag( name: "summary", value: "Get Cisco IOS Software Version via SSH." );
	script_dependencies( "gb_cisco_show_version.sc" );
	script_mandatory_keys( "cisco/show_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
source = "ssh";
if(!show_ver = get_kb_item( "cisco/show_version" )){
	exit( 0 );
}
if(!ContainsString( show_ver, "Cisco IOS Software" ) || ContainsString( show_ver, "IOS XE" ) || ContainsString( show_ver, "IOS-XE" )){
	exit( 0 );
}
set_kb_item( name: "cisco/show_ver", value: show_ver );
set_kb_item( name: "cisco_ios/detected", value: TRUE );
version = "unknown";
sv = split( buffer: show_ver, keep: FALSE );
for line in sv {
	if(IsMatchRegexp( line, "^.*IOS.*Version [0-9.]+" ) && !ContainsString( line, "IOS XE" )){
		vers = eregmatch( pattern: "Version ([^ ,\\r\\n]+)", string: line );
		break;
	}
}
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "cisco_ios/" + source + "/version", value: vers[1] );
}
model = eregmatch( pattern: "cisco ([^\\(]+) \\([^\\)]+\\) processor", string: show_ver );
if(!isnull( model[1] )){
	set_kb_item( name: "cisco_ios/" + source + "/model", value: model[1] );
}
image = eregmatch( pattern: "\\(([^)]+)\\), *Version", string: show_ver );
if(!isnull( image[1] )){
	set_kb_item( name: "cisco_ios/" + source + "/image", value: image[1] );
}
exit( 0 );

