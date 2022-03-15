if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140136" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-01-31 14:38:46 +0100 (Tue, 31 Jan 2017)" );
	script_name( "EMC Secure Remote Services Detection" );
	script_tag( name: "summary", value: "This script performs SSH based detection of EMC Secure Remote Services" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ems/esrs/rls" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!version = get_kb_item( "ems/esrs/rls" )){
	exit( 0 );
}
cpe = "cpe:/a:emc:secure_remote_services:" + version;
register_product( cpe: cpe, location: "ssh", service: "ssh" );
report = build_detection_report( app: "EMC Secure Remote Services", version: version, install: "ssh", cpe: cpe, concluded: "/etc/esrs-release" );
log_message( port: 0, data: report );
exit( 0 );

