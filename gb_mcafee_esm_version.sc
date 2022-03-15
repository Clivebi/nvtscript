if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105477" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-12-04 13:23:42 +0100 (Fri, 04 Dec 2015)" );
	script_name( "McAfee Enterprise Security Manager Detection" );
	script_tag( name: "summary", value: "This script performs SSH based detection of McAfee Enterprise Security Manager" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "mcafee/etm/buildinfo" );
	exit( 0 );
}
require("host_details.inc.sc");
buildinfo = get_kb_item( "mcafee/etm/buildinfo" );
if(!buildinfo){
	exit( 0 );
}
cpe = "cpe:/a:mcafee:enterprise_security_manager";
vers = "unknown";
mr = 0;
version = eregmatch( pattern: "VERSION=([^\r\n ]+)", string: buildinfo );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "mcafee/esm/version", value: vers );
}
maintver = eregmatch( pattern: "MAINTVER=([^\r\n ]+)", string: buildinfo );
if(!isnull( maintver[1] )){
	mr = maintver[1];
	cpe += "mr" + mr;
	set_kb_item( name: "mcafee/esm/mr", value: mr );
}
register_product( cpe: cpe, location: "ssh" );
log_message( data: build_detection_report( app: "McAfee Enterprise Security Manager", version: vers, install: "ssh", cpe: cpe, concluded: "/etc/NitroGuard/.buildinfo" ), port: 0 );
exit( 0 );

