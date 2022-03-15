if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108284" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-10-27 07:13:48 +0200 (Fri, 27 Oct 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (HNAP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_hnap_detect.sc" );
	script_mandatory_keys( "HNAP/port" );
	script_tag( name: "summary", value: "Home Network Administration Protocol (HNAP) based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (HNAP)";
BANNER_TYPE = "HNAP device info";
if(!port = get_kb_item( "HNAP/port" )){
	exit( 0 );
}
vendor = get_kb_item( "HNAP/" + port + "/vendor" );
model = get_kb_item( "HNAP/" + port + "/model" );
banner = vendor + " " + model;
if(!banner || strlen( banner ) <= 1){
	exit( 0 );
}
if(ContainsString( banner, "SMC Inc. SMCWBR14S" ) || ContainsString( banner, "Linksys " )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "^D-Link (DAP|DIR|DNS|DSL|DWR)" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "hnap_device_info", port: port );
exit( 0 );

