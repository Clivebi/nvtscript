CPE = "cpe:/a:sendmail:sendmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11086" );
	script_version( "$Revision: 13074 $" );
	script_bugtraq_id( 3377 );
	script_cve_id( "CVE-2001-0713" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-15 10:12:34 +0100 (Tue, 15 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Sendmail custom configuration file" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2002 Michel Arboi" );
	script_family( "SMTP problems" );
	script_dependencies( "gb_sendmail_detect.sc" );
	script_mandatory_keys( "sendmail/detected" );
	script_tag( name: "solution", value: "Upgrade to the latest version of Sendmail." );
	script_tag( name: "summary", value: "The remote sendmail server, according to its version number,
  may be vulnerable to a 'Mail System Compromise' when a user supplies a custom configuration file.
  Although the mail server is suppose to run as a lambda user, a programming error allows the local
  attacker to regain the extra dropped privileges and run commands as root.

  Note: This vulnerability is _local_ only" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^8\\.12\\.0.*" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "> 8.12.0.x" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

