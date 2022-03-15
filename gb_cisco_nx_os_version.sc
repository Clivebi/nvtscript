if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105690" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-05-12 12:21:43 +0200 (Thu, 12 May 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Report Cisco NX-OS Software Version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_cisco_nx_os_detect.sc", "gb_cisco_nx_os_detect_ssh.sc" );
	script_mandatory_keys( "cisco/nx_os/detected" );
	script_tag( name: "summary", value: "Report the Cisco NX-OS Software Version." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
cpe = "cpe:/o:cisco:nx-os";
version = "unknown";
source = "ssh";
if(!version = get_kb_item( "cisco/nx_os/" + source + "/version" )){
	source = "snmp";
	if(!version = get_kb_item( "cisco/nx_os/" + source + "/version" )){
		exit( 0 );
	}
}
if(!isnull( version )){
	cpe += ":" + version;
	set_kb_item( name: "cisco_nx_os/version", value: version );
}
if(model = get_kb_item( "cisco/nx_os/" + source + "/model" )){
	if(model == "MDS"){
		model = "unknown";
	}
	set_kb_item( name: "cisco_nx_os/model", value: model );
}
if(device = get_kb_item( "cisco/nx_os/" + source + "/device" )){
	set_kb_item( name: "cisco_nx_os/device", value: device );
}
register_product( cpe: cpe, location: source );
os_register_and_report( os: "Cisco NX OS", cpe: cpe, banner_type: toupper( source ), desc: "Report Cisco NX-OS Software Version", runs_key: "unixoide" );
report = "Detected Cisco NX-OS\n" + "Version: " + version + "\n" + "CPE:     " + cpe + "\n";
if(model){
	report += "Model:   " + model + "\n";
}
if(device){
	report += "Typ:     " + device + "\n";
}
report += "Detection source: " + source + "\n";
log_message( port: 0, data: report );
exit( 0 );

