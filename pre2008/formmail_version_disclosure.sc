CPE = "cpe:/a:matt_wright:formmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10782" );
	script_version( "$Revision: 5864 $" );
	script_tag( name: "last_modification", value: "$Date: 2017-04-05 09:47:30 +0200 (Wed, 05 Apr 2017) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0357" );
	script_name( "FormMail Insufficient Spam Protection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2001 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "FormMail_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "FormMail/installed" );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_tag( name: "summary", value: "Matt Wright's FormMail CGI is installed on the remote host.

  FormMail.pl in FormMail 1.6 and earlier allows a remote attacker to send anonymous email (spam)
  by modifying the recipient and message parameters." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "1.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.7" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

