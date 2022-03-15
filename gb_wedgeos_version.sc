if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105312" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-07-02 16:13:36 +0200 (Thu, 02 Jul 2015)" );
	script_name( "wedgeOS Detection" );
	script_tag( name: "summary", value: "This script performs SSH based detection of wedgeOS" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "wedgeOS/status" );
	exit( 0 );
}
require("host_details.inc.sc");
status = get_kb_item( "wedgeOS/status" );
if(!ContainsString( status, "BeSecure" )){
	exit( 0 );
}
cpe = "cpe:/a:wedge_networks:wedgeos";
vers = "unknown";
install = "ssh";
version = eregmatch( pattern: "Version ([0-9.-]+)", string: status );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
}
register_product( cpe: cpe, location: install );
log_message( data: build_detection_report( app: "wedgeOS", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: 0 );
exit( 0 );

