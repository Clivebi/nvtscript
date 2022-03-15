CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106804" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-15 13:21:35 +0700 (Mon, 15 May 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-8114" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail Password Reset Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "Roundcube Webmail is prone to an arbitrary password reset vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in the virtualmin and sasl drivers of the password plugin
allows authenticated users to reset arbitrary passwords." );
	script_tag( name: "affected", value: "Roundcube Webmail prior version 1.0.11, 1.1.x and 1.2.x." );
	script_tag( name: "solution", value: "Update to version, 1.0.11, 1.1.9, 1.2.5 or later." );
	script_xref( name: "URL", value: "https://roundcube.net/news/2017/04/28/security-updates-1.2.5-1.1.9-and-1.0.11" );
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
if(version_is_less( version: version, test_version: "1.0.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.11", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.1", test_version2: "1.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.9", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.2", test_version2: "1.2.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.5", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

