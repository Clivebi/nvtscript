if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105462" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-20 12:48:40 +0100 (Fri, 20 Nov 2015)" );
	script_name( "Cisco Mobility Service Engine Detection (SSH)" );
	script_tag( name: "summary", value: "This script performs SSH based detection of Cisco Mobility Service Engine" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "cisco_mse/status" );
	exit( 0 );
}
status = get_kb_item( "cisco_mse/status" );
if(!status || ( !ContainsString( status, "Cisco Mobility Service Engine" ) && !ContainsString( status, "Build Version" ) )){
	exit( 0 );
}
if( ContainsString( status, "Product name: Cisco Mobility Service Engine" ) ) {
	version = eregmatch( pattern: "Product name: Cisco Mobility Service Engine[\r\n]+Version: ([^\r\n]+)", string: status );
}
else {
	version = eregmatch( pattern: "Build Version\\s*:\\s*([0-9]+[^\r\n]+)", string: status );
}
if(!isnull( version[1] )){
	set_kb_item( name: "cisco_mse/ssh/version", value: version[1] );
	set_kb_item( name: "cisco_mse/lsc", value: TRUE );
	vers = version[1];
}
exit( 0 );

