if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108455" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-08-06 13:53:41 +0200 (Mon, 06 Aug 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (NNTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "nntpserver_detect.sc" );
	script_mandatory_keys( "nntp/detected" );
	script_tag( name: "summary", value: "NNTP server based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("nntp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (NNTP)";
BANNER_TYPE = "NNTP Server banner";
port = nntp_get_port( default: 119 );
if(!banner = get_kb_item( "nntp/banner/" + port )){
	exit( 0 );
}
if(ContainsString( banner, "Kerio Connect" ) || ContainsString( banner, "Kerio MailServer" )){
	exit( 0 );
}
if(banner == "200 NNTP server ready" || banner == "201 NNTP server ready (no posting)"){
	exit( 0 );
}
if(IsMatchRegexp( banner, "^200 NNTP Service [0-9.]+ Version: [0-9.]+ Posting Allowed$" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(banner == "200 CCProxy NNTP Service"){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "NNTP-Server Classic Hamster" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, " Leafnode NNTP " )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, " NNTP Citadel server " )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( banner, "(Mailtraq " ) && ContainsString( banner, "NNTP)" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "Lotus Domino NNTP Server for Windows" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, " InterNetNews NNRP server " )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "nntp_banner", port: port );
exit( 0 );

