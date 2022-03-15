if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105621" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-04-26 11:14:43 +0200 (Tue, 26 Apr 2016)" );
	script_name( "Cyberoam Central Console Detection" );
	script_tag( name: "summary", value: "This script performs SSH based detection of Cyberoam Central Console" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "cyberoam_cc/version_info" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!sysinfo = get_kb_item( "cyberoam_cc/version_info" )){
	exit( 0 );
}
cpe = "cpe:/a:cyberoam:cyberoam_central_console";
vers = "unknown";
version = eregmatch( pattern: "CCC version:\\s*([0-9.]+[^ ]+) ", string: sysinfo );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "cyberoam_cc/version", value: vers );
}
mod = eregmatch( pattern: "CCC Model:\\s*(CCC[^ \r\n]+)", string: sysinfo );
if(!isnull( mod[1] )){
	model = mod[1];
	set_kb_item( name: "cyberoam_cc/model", value: model );
}
_build = eregmatch( pattern: "CCC version:\\s*[0-9.]+[^ ]+ build ([0-9]+[^ \r\n]+)", string: sysinfo );
if(!isnull( _build[1] )){
	build = _build[1];
	set_kb_item( name: "cyberoam_cc/build", value: build );
}
hf = eregmatch( pattern: "Hot Fix version:\\s*([^\r\n]+)", string: sysinfo );
if(!isnull( hf[1] ) && hf[1] != "N.A"){
	hotfix = hf[1];
	set_kb_item( name: "cyberoam_cc/hotfix", value: hotfix );
}
register_product( cpe: cpe, location: "ssh" );
report = "Detected Cyberoam Central Console\n" + "Version: " + vers;
if(build){
	report += "\nBuild:   " + build;
}
if(model){
	report += "\nModel:   " + model;
}
if(hotfix){
	report += "\nInstalled hostfix: " + hotfix;
}
log_message( port: 0, data: report );
exit( 0 );

