if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105441" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-11-09 13:54:40 +0100 (Mon, 09 Nov 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cisco Web Security Appliance Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wsa_web_detect.sc", "gather-package-list.sc" );
	script_mandatory_keys( "cisco_wsa/installed" );
	script_tag( name: "summary", value: "This Script get the via HTTP(s) or SSH detected Cisco Web Security Appliance
version." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
source = "SSH";
version = get_kb_item( "cisco_wsa/version/ssh" );
if(!version){
	version = get_kb_item( "cisco_wsa/version/http" );
	source = "HTTP(s)";
}
if(!version){
	exit( 0 );
}
model = get_kb_item( "cisco_wsa/model/ssh" );
if(!model){
	model = get_kb_item( "cisco_wsa/model/http" );
}
set_kb_item( name: "cisco_wsa/version", value: version );
if(model){
	set_kb_item( name: "cisco_wsa/model", value: model );
}
cpe = "cpe:/h:cisco:web_security_appliance:" + version;
register_product( cpe: cpe );
os_register_and_report( os: "Cisco AsyncOS", cpe: "cpe:/o:cisco:asyncos:" + version, banner_type: source, desc: "Cisco Web Security Appliance Detection", runs_key: "unixoide" );
report = "Detected Cisco Web Security Appliance\nVersion: " + version + "\nCPE: " + cpe;
if(model){
	report += "\nModel: " + model;
}
report += "\nDetection source: " + source;
log_message( port: 0, data: report );
exit( 0 );

