CPE = "cpe:/a:ipswitch:ws_ftp_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14584" );
	script_version( "2019-06-26T08:42:42+0000" );
	script_tag( name: "last_modification", value: "2019-06-26 08:42:42 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1643" );
	script_bugtraq_id( 11065 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "WS FTP server DoS" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "FTP" );
	script_dependencies( "secpod_wsftp_win_detect.sc" );
	script_mandatory_keys( "ipswitch/ws_ftp_server/detected" );
	script_tag( name: "summary", value: "According to its version number, the remote WS_FTP server is vulnerable to
  a remote denial of service." );
	script_tag( name: "impact", value: "There is an error in the parsing of file paths.  Exploitation of this flaw
  may cause a vulnerable system to use a large amount of CPU resources.

  Successful exploitation requires that the user has been authenticated." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software." );
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
if(IsMatchRegexp( version, "^[0-4]\\.|5\\.[0-2][^0-9]" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

