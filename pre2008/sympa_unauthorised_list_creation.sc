CPE = "cpe:/a:sympa:sympa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14300" );
	script_version( "2020-02-25T07:14:55+0000" );
	script_tag( name: "last_modification", value: "2020-02-25 07:14:55 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 10941 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_name( "Sympa < 4.1.2 Authentication Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "sympa_detect.sc" );
	script_mandatory_keys( "sympa/detected" );
	script_tag( name: "solution", value: "Update to version 4.1.2 or newer." );
	script_tag( name: "summary", value: "The version of Sympa has an authentication flaw within the web interface." );
	script_tag( name: "impact", value: "An attacker, exploiting this flaw, would be able to bypass security
  mechanisms resulting in the ability to perform listmaster functions remotely." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "4.1.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

