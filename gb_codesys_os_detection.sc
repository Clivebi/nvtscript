if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108494" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-12-04 13:25:20 +0100 (Tue, 04 Dec 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (CODESYS)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_codesys_detect.sc" );
	script_mandatory_keys( "codesys/detected" );
	script_tag( name: "summary", value: "CODESYS programming interface based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (CODESYS)";
BANNER_TYPE = "CODESYS Service information";
port = service_get_port( default: 2455, proto: "codesys" );
if(!os_name = get_kb_item( "codesys/" + port + "/os_name" )){
	exit( 0 );
}
if(!os_details = get_kb_item( "codesys/" + port + "/os_details" )){
	exit( 0 );
}
report_banner = "\nOS Name:    " + os_name;
report_banner += "\nOS Details: " + os_details;
if( os_name == "Windows" ){
	ce_ver = eregmatch( pattern: "^CE ([0-9.]+)", string: os_details );
	if(!isnull( ce_ver[1] )){
		os_register_and_report( os: "Microsoft Windows CE", version: ce_ver[1], cpe: "cpe:/o:microsoft:windows_ce", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	ce_ver = eregmatch( pattern: "^CE\\.net \\(([0-9.x]+)", string: os_details );
	if(!isnull( ce_ver[1] )){
		os_register_and_report( os: "Microsoft Windows CE.net", version: ce_ver[1], cpe: "cpe:/o:microsoft:windows_ce", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(ContainsString( os_details, "unknown CE version" )){
		os_register_and_report( os: "Microsoft Windows CE", cpe: "cpe:/o:microsoft:windows_ce", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(ContainsString( os_details, "NT/2000/XP" )){
		os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	os_register_unknown_banner( banner: report_banner, banner_type_name: BANNER_TYPE, banner_type_short: "codesys_banner", port: port );
}
else {
	if( os_name == "Linux" ){
		version = eregmatch( pattern: "^([0-9.]+)", string: os_details );
		if( !isnull( version[1] ) ){
			os_register_and_report( os: "Linux", version: version[1], cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
	}
	else {
		if( os_name == "Nucleus PLUS" ){
			os_register_and_report( os: "Nucleus RTOS", cpe: "cpe:/o:mentor:nucleus_rtos", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			if(ContainsString( os_details, "Nucleus PLUS version unknown" )){
				exit( 0 );
			}
			os_register_unknown_banner( banner: report_banner, banner_type_name: BANNER_TYPE, banner_type_short: "codesys_banner", port: port );
		}
		else {
			if( os_name == "VxWorks" ){
				version = eregmatch( pattern: "^([0-9.]+)", string: os_details );
				if( !isnull( version[1] ) ){
					os_register_and_report( os: "Wind River VxWorks", version: version[1], cpe: "cpe:/o:windriver:vxworks", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "Wind River VxWorks", cpe: "cpe:/o:windriver:vxworks", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
			}
			else {
				if( os_name == "@CHIP-RTOS" ){
					version = eregmatch( pattern: "^[^ ]+ V([0-9.]+)", string: os_details );
					if( !isnull( version[1] ) ){
						os_register_and_report( os: "@CHIP-RTOS", version: version[1], cpe: "cpe:/o:beck-ipc:chip-rtos", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "@CHIP-RTOS", cpe: "cpe:/o:beck-ipc:chip-rtos", banner_type: BANNER_TYPE, port: port, banner: report_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
				}
				else {
					os_register_unknown_banner( banner: report_banner, banner_type_name: BANNER_TYPE, banner_type_short: "codesys_banner", port: port );
				}
			}
		}
	}
}
exit( 0 );

