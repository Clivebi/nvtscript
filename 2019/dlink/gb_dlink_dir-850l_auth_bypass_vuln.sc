if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113332" );
	script_version( "2020-05-15T10:17:31+0000" );
	script_tag( name: "last_modification", value: "2020-05-15 10:17:31 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "creation_date", value: "2019-02-07 14:51:44 +0100 (Thu, 07 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-18907" );
	script_name( "D-Link DIR-850L FW < 1.21B07 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_mandatory_keys( "d-link/dir/fw_version", "d-link/dir/hw_version" );
	script_tag( name: "summary", value: "D-Link DIR-850L is prone
  to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable firmware version
  is installed on the target device." );
	script_tag( name: "insight", value: "The vulnerability exists due to the router allowing
  clients to communicate with it without completing the full WPA handshake." );
	script_tag( name: "impact", value: "Successful exploitation would allow an unauthenticated attacker
  to register as a client in the router's network." );
	script_tag( name: "affected", value: "D-Link DIR-850L all revision A devices
  with firmware version 1.21B06 or prior." );
	script_tag( name: "solution", value: "Update to firmware version 1.21B07." );
	script_xref( name: "URL", value: "https://www.synopsys.com/blogs/software-security/cve-2018-18907/" );
	exit( 0 );
}
CPE = "cpe:/o:d-link:dir-850l_firmware";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!fw_vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!hw_vers = get_kb_item( "d-link/dir/hw_version" )){
	exit( 0 );
}
hw_vers = toupper( hw_vers );
fw_vers = toupper( fw_vers );
if(IsMatchRegexp( hw_vers, "^a" ) && version_is_less( version: fw_vers, test_version: "1.21B07" )){
	report = report_fixed_ver( installed_version: fw_vers, fixed_version: "1.21B07", extra: "Hardware revision: " + hw_vers );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

