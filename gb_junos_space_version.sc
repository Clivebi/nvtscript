if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105407" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-10-16 19:26:14 +0200 (Fri, 16 Oct 2015)" );
	script_name( "JunOS Space Detection" );
	script_tag( name: "summary", value: "The script performs ssh based detection of JunOS Space" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "junos/space" );
	exit( 0 );
}
require("host_details.inc.sc");
cpe = "cpe:/a:juniper:junos_space";
rls = get_kb_item( "junos/space" );
if(!rls || !IsMatchRegexp( rls, "Space release [0-9][0-9.]+([^0-9.][0-9.]+)? \\((dev.)?[0-9]+\\)" )){
	exit( 0 );
}
set_kb_item( name: "junos_space/installed", value: TRUE );
version = eregmatch( pattern: "Space release ([0-9][0-9.]+([^0-9.][0-9.]+)?) \\((dev.)?([0-9]+)\\)", string: rls );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
}
if(!isnull( version[4] )){
	build = version[4];
	set_kb_item( name: "junos_space/build", value: build );
}
register_product( cpe: cpe, location: "ssh" );
log_message( data: build_detection_report( app: "JunOS Space", version: vers, install: "ssh", cpe: cpe, concluded: version[0] ), port: 0 );
exit( 0 );

