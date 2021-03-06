CPE = "cpe:/a:ipswitch:ws_ftp_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11098" );
	script_version( "2019-06-26T08:42:42+0000" );
	script_tag( name: "last_modification", value: "2019-06-26 08:42:42 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5427 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0826" );
	script_name( "WS_FTP SITE CPWD Buffer Overflow" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "This script is Copyright (C) 2002 Digital Defense, Inc." );
	script_dependencies( "secpod_wsftp_win_detect.sc" );
	script_mandatory_keys( "ipswitch/ws_ftp_server/detected" );
	script_tag( name: "summary", value: "This host is running a version of WS_FTP FTP server prior to 3.1.2." );
	script_tag( name: "insight", value: "Versions earlier than 3.1.2 contain an unchecked buffer in routines that
  handle the 'CPWD' command arguments. The 'CPWD' command allows remote users to change their password. By
  issuing a malformed argument to the CPWD command, a user could overflow a buffer and execute arbitrary code
  on this host. Note that a local user account is required." );
	script_tag( name: "solution", value: "The vendor has released a patch that fixes this issue. Please install
  the latest patch available from the vendor's website." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: version, test_version: "3.1.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

