if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105802" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 12780 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-13 03:31:17 +0100 (Thu, 13 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2016-07-07 16:59:41 +0200 (Thu, 07 Jul 2016)" );
	script_name( "QRadar Detection" );
	script_tag( name: "summary", value: "The script performs SSH  based detection of QRadar" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "qradar/version" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!version = get_kb_item( "qradar/version" )){
	exit( 0 );
}
cpe = "cpe:/a:ibm:qradar_security_information_and_event_manager:" + version;
register_product( cpe: cpe, location: "ssh" );
report = build_detection_report( app: "QRadar", version: version, install: "ssh", cpe: cpe );
log_message( port: 0, data: report );
exit( 0 );

