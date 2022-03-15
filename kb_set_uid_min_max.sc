if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150137" );
	script_version( "2020-07-29T11:15:13+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 11:15:13 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-02-19 09:51:58 +0000 (Wed, 19 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Get UID variables from /etc/login.defs" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_login_defs.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "http://man7.org/linux/man-pages/man5/login.defs.5.html" );
	script_tag( name: "summary", value: "The /etc/login.defs file defines the site-specific configuration
for the shadow password suite. This file is required. Absence of this file will not prevent system
operation, but will probably result in undesirable operation.

This script reads and stores variables SYS_UID_MAX, SYS_UID_MIN, UID_MAX and UID_MIN.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
if( get_kb_item( "Policy/linux//etc/login.defs/ERROR" ) ){
	exit( 0 );
}
else {
	content = get_kb_item( "Policy/linux//etc/login.defs/content" );
	for line in split( buffer: content, keep: FALSE ) {
		match = eregmatch( string: line, pattern: "^\\s*(SYS_UID_MIN|SYS_UID_MAX|UID_MIN|UID_MAX)\\s*([0-9]*)" );
		if(match){
			set_kb_item( name: "Policy/linux//etc/login.defs/" + match[1], value: match[2] );
		}
	}
}
exit( 0 );

