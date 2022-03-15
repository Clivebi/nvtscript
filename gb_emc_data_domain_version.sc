if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140143" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)" );
	script_name( "EMC Data Domain Version Report" );
	script_tag( name: "summary", value: "This script consolidate and report the detected version of EMC Data Domain Version." );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_emc_data_domain_detect_snmp.sc", "gb_emc_data_domain_detect_ssh.sc", "gb_emc_data_domain_detect_www.sc" );
	script_mandatory_keys( "emc/data_domain/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
source = "ssh";
version = get_kb_item( "emc/data_domain/version/" + source );
if(!version){
	source = "http";
	version = get_kb_item( "emc/data_domain/version/" + source );
}
if(!version){
	source = "snmp";
	version = get_kb_item( "emc/data_domain/version/" + source );
}
cpe = "cpe:/a:emc:data_domain_os";
if( version ){
	set_kb_item( name: "emc/data_domain/version", value: version );
	cpe += ":" + version;
}
else {
	version = "unknown";
}
register_product( cpe: cpe, location: source );
if(build = get_kb_item( "emc/data_domain/build/" + source )){
	set_kb_item( name: "emc/data_domain/build", value: build );
}
if(model = get_kb_item( "emc/data_domain/model/" + source )){
	set_kb_item( name: "emc/data_domain/model", value: model );
}
report = "Detected EMC Data Domain\n\n" + "Version:  " + version + "\n";
if(build){
	report += "Build:    " + build + "\n";
}
if(model){
	report += "Model:    " + model + "\n";
}
report += "CPE:      " + cpe + "\n\n" + "Detection source: " + source + "\n";
log_message( port: 0, data: report );
exit( 0 );

