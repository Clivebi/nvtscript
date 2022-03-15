CPE = "cpe:/a:concrete5:concrete5";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112595" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-19 13:19:12 +0200 (Wed, 19 Jun 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 20:43:00 +0000 (Thu, 15 Jul 2021)" );
	script_cve_id( "CVE-2018-19146" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Concrete5 <= 8.4.3 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_concrete5_detect.sc" );
	script_mandatory_keys( "concrete5/installed" );
	script_tag( name: "summary", value: "Concrete5 is prone to a stored cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists because config/concrete.php allows uploads
  (by administrators) of SVG files that may contain HTML data with a SCRIPT element." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker
  to store malicious code inside the application which is then being executed when browsing to an affected site." );
	script_tag( name: "affected", value: "Concrete5 through version 8.4.3." );
	script_tag( name: "solution", value: "Update to version 8.4.4 or later." );
	script_xref( name: "URL", value: "https://hackerone.com/reports/437863" );
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
path = infos["location"];
if(version_is_less( version: version, test_version: "8.4.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.4.4", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

