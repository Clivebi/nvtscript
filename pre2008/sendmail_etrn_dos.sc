CPE = "cpe:/a:sendmail:sendmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11350" );
	script_version( "$Revision: 13074 $" );
	script_bugtraq_id( 904 );
	script_cve_id( "CVE-1999-1109" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-15 10:12:34 +0100 (Tue, 15 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Sendmail ETRN command DOS" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 Xue Yong Zhi" );
	script_family( "SMTP problems" );
	script_dependencies( "gb_sendmail_detect.sc" );
	script_mandatory_keys( "sendmail/detected" );
	script_tag( name: "solution", value: "Install sendmail version 8.10.1 and higher, or
  install a vendor supplied patch." );
	script_tag( name: "summary", value: "The remote sendmail server, according to its version number,
  allows remote attackers to cause a denial of service by sending a series of ETRN commands then
  disconnecting from the server, while Sendmail continues to process the commands
  after the connection has been terminated." );
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
if(IsMatchRegexp( vers, "^8\\.([0-9]|[0-9]\\.[0-9]+|10\\.0)$" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.10.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

