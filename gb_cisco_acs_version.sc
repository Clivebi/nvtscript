if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105464" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-23 16:23:17 +0100 (Mon, 23 Nov 2015)" );
	script_name( "Cisco Secure Access Control System Detection" );
	script_tag( name: "summary", value: "This script performs ssh based detection of Cisco Secure Access Control System" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "cisco_acs/show_ver" );
	exit( 0 );
}
require("host_details.inc.sc");
show_ver = get_kb_item( "cisco_acs/show_ver" );
if(!show_ver || !ContainsString( show_ver, "Cisco ACS VERSION INFORMATION" )){
	exit( 0 );
}
cpe = "cpe:/a:cisco:secure_access_control_system";
vers = "unknown";
version = eregmatch( pattern: "[^ ]Version\\s*:\\s*([0-9]+[^\r\n]+)", string: show_ver );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "cisco_acs/version", value: vers );
	cpe += ":" + vers;
}
register_product( cpe: cpe, location: "ssh" );
log_message( data: build_detection_report( app: "Cisco Secure Access Control System", version: vers, install: "ssh", cpe: cpe, concluded: "show version" ), port: 0 );
exit( 0 );

