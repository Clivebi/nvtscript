CPE = "cpe:/a:sendmail:sendmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11087" );
	script_version( "$Revision: 13074 $" );
	script_bugtraq_id( 3378 );
	script_cve_id( "CVE-2001-0714" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-15 10:12:34 +0100 (Tue, 15 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Sendmail queue manipulation & destruction" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2002 Michel Arboi" );
	script_family( "SMTP problems" );
	script_dependencies( "gb_sendmail_detect.sc" );
	script_mandatory_keys( "sendmail/detected" );
	script_tag( name: "solution", value: "Upgrade to the latest version of Sendmail or
  do not allow users to process the queue (RestrictQRun option)." );
	script_tag( name: "summary", value: "The remote sendmail server, according to its version number,
  might be vulnerable to a queue destruction." );
	script_tag( name: "impact", value: "The flaw might happen when a local user runs:

  sendmail -q -h1000

  If you system does not allow users to process the queue (which
  is the default), you are not vulnerable.

  Note: This vulnerability is _local_ only." );
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
if(IsMatchRegexp( vers, "^8\\.(([0-9]\\..*)|(1[01]\\..*)|(12\\.0))$" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See solution tag." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

