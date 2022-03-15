if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105751" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-06-10 11:52:17 +0200 (Fri, 10 Jun 2016)" );
	script_name( "VMware vRealize Log Insight Detection" );
	script_tag( name: "summary", value: "This script perform ssh based detection of VMware vRealize Log Insight" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_vrealize_log_insight_web_interface_detect.sc" );
	script_mandatory_keys( "vmware/vrealize_log_insight/rls" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!rls = get_kb_item( "vmware/vrealize_log_insight/rls" )){
	exit( 0 );
}
cpe = "cpe:/a:vmware:vrealize_log_insight";
vers = "unknown";
version = eregmatch( pattern: "VMware vRealize Log Insight ([0-9]+[^ ]+) Build ([0-9]+[^ \r\n]+)", string: rls );
if(!isnull( version[1] )){
	vers = version[1];
	rep_vers = vers;
	set_kb_item( name: "vmware/vrealize_log_insight/version", value: vers );
	cpe += ":" + vers;
}
if(!isnull( version[2] )){
	build = version[2];
	set_kb_item( name: "vmware/vrealize_log_insight/build", value: build );
	rep_vers = rep_vers + " Build " + build;
}
source = "ssh";
if(ContainsString( rls, "ds:www" )){
	source = "www";
}
register_product( cpe: cpe, location: source );
log_message( port: 0, data: build_detection_report( app: "VMware vRealize Log Insight", version: rep_vers, install: source, cpe: cpe, concluded: version[0] ) );
exit( 0 );

