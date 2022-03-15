CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14344" );
	script_version( "2019-09-07T11:55:45+0000" );
	script_tag( name: "last_modification", value: "2019-09-07 11:55:45 +0000 (Sat, 07 Sep 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9184 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Mantis multiple unspecified XSS" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Mantis 0.18.1 or newer." );
	script_tag( name: "summary", value: "According to its banner, the remote version of Mantis contains a flaw
  in the handling of some types of input." );
	script_tag( name: "impact", value: "Because of this, an attacker may be able to cause arbitrary HTML and
  script code to be executed in a user's browser within the security context of the affected web site." );
	script_xref( name: "URL", value: "http://sourceforge.net/project/shownotes.php?release_id=202559" );
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
if(version_is_less( version: version, test_version: "0.18.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.18.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

