if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105814" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-07-19 09:58:46 +0200 (Tue, 19 Jul 2016)" );
	script_name( "FortiManager Detection" );
	script_tag( name: "summary", value: "This script performs SSH based detection of FortiManager" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "FortiOS/system_status" );
	exit( 0 );
}
require("host_details.inc.sc");
system = get_kb_item( "FortiOS/system_status" );
if(!ContainsString( system, "FortiManager" )){
	exit( 0 );
}
cpe = "cpe:/h:fortinet:fortimanager";
m = eregmatch( pattern: "Platform Full Name\\s*:\\s*FortiManager-([^ \r\n]+)", string: system );
if(!isnull( m[1] )){
	model = m[1];
	set_kb_item( name: "fortimanager/model", value: model );
}
vers = "unknown";
if(version = get_kb_item( "forti/FortiOS/version" )){
	vers = version;
	cpe += ":" + vers;
	set_kb_item( name: "fortimanager/version", value: TRUE );
}
rep_vers = vers;
if(build = get_kb_item( "forti/FortiOS/build" )){
	set_kb_item( name: "fortimanager/build", value: build );
	rep_vers += " Build " + build;
}
register_product( cpe: cpe, location: "ssh", service: "ssh" );
report = build_detection_report( app: "FortiManager", version: rep_vers, install: "ssh", cpe: cpe, concluded: system );
log_message( port: 0, data: report );
exit( 0 );

