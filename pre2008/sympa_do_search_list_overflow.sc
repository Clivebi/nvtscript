CPE = "cpe:/a:sympa:sympa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14298" );
	script_version( "2020-02-25T07:14:55+0000" );
	script_tag( name: "last_modification", value: "2020-02-25 07:14:55 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "OSVDB", value: "8690" );
	script_name( "Sympa < 4.1.2 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "sympa_detect.sc" );
	script_mandatory_keys( "sympa/detected" );
	script_tag( name: "solution", value: "Update to version 4.1.2 or newer." );
	script_tag( name: "summary", value: "This version of Sympa has a flaw in one of it's scripts
  (wwsympa.pl) which would allow a remote attacker to overflow the sympa server. Specifically,
  within the cgi script wwsympa.pl is a do_search_list function which fails to perform
  bounds checking." );
	script_tag( name: "impact", value: "An attacker, passing a specially formatted long string
  to this function, would be able to crash the remote sympa server. At the
  time of this writing, the attack is only known to cause a Denial of Service (DoS)." );
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

