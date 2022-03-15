CPE = "cpe:/a:sympa:sympa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16387" );
	script_version( "2020-02-25T07:14:55+0000" );
	script_tag( name: "last_modification", value: "2020-02-25 07:14:55 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 12527 );
	script_cve_id( "CVE-2005-0073" );
	script_name( "Sympa < 4.1.3 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "sympa_detect.sc" );
	script_mandatory_keys( "sympa/detected" );
	script_tag( name: "solution", value: "Update to Sympa version 4.1.3 or newer." );
	script_tag( name: "summary", value: "The remote version of Sympa contains a vulnerability which can be
  exploited by malicious local user to gain escalated privileges." );
	script_tag( name: "impact", value: "This issue is due to a boundary error in the queue utility when
  processing command line arguments. This can cause a stack based buffer overflow." );
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
if(version_is_less( version: version, test_version: "4.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

