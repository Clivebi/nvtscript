CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11343" );
	script_version( "2019-05-22T07:58:25+0000" );
	script_cve_id( "CVE-2000-1169" );
	script_bugtraq_id( 1949 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-05-22 07:58:25 +0000 (Wed, 22 May 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "OpenSSH Client Unauthorized Remote Forwarding" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 Xue Yong Zhi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_tag( name: "solution", value: "Patch and new version are available from OpenSSH." );
	script_tag( name: "summary", value: "The remote host is running OpenSSH SSH client before 2.3.0." );
	script_tag( name: "insight", value: "This version does not properly disable X11 or agent forwarding,
  which could allow a malicious SSH server to gain access to the X11 display and sniff X11 events,
  or gain access to the ssh-agent." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "2.3.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.0", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

