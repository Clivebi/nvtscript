CPE = "cpe:/a:ipswitch:ws_ftp_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14585" );
	script_version( "2019-06-26T08:42:42+0000" );
	script_tag( name: "last_modification", value: "2019-06-26 08:42:42 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3507 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "WS FTP STAT buffer overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "FTP" );
	script_dependencies( "secpod_wsftp_win_detect.sc" );
	script_mandatory_keys( "ipswitch/ws_ftp_server/detected" );
	script_tag( name: "summary", value: "According to its version number, your remote WS_FTP server is vulnerable
  to a buffer overflow." );
	script_tag( name: "impact", value: "A logged attacker submitting a 'STAT' command along with
  arbitrary characters can potentially execute arbitrary code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^1\\.|2\\.(0[^0-9]|0\\.[0-3][^0-9])" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

