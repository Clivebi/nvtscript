if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14597" );
	script_version( "2020-03-11T09:57:55+0000" );
	script_tag( name: "last_modification", value: "2020-03-11 09:57:55 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 547 );
	script_cve_id( "CVE-1999-1078" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WS_FTP client weak stored password" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Windows" );
	script_dependencies( "secpod_ws_ftp_client_detect.sc" );
	script_mandatory_keys( "Ipswitch/WS_FTP_Pro/Client/Ver" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the newest version of the WS_FTP client." );
	script_tag( name: "summary", value: "The remote host has a version of the WS_FTP client which use a weak
  encryption method to store site password." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:ipswitch:ws_ftp";
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ftpVer = infos["version"];
loc = infos["location"];
if(version_is_less_equal( version: ftpVer, test_version: "2007.0.0.2" )){
	report = report_fixed_ver( installed_version: ftpVer, fixed_version: "12.6", install_path: loc );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

