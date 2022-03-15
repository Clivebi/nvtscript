CPE = "cpe:/a:facebook:hhvm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142449" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-05-17 09:18:41 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:49:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2019-3561" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HHVM Memory Corruption Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hhvm_detect.sc" );
	script_mandatory_keys( "HHVM/detected" );
	script_tag( name: "summary", value: "HHMV is prone to a vulnerability where unintended memory locations are possible
  to access." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Insufficient boundary checks for the strrpos and strripos functions allow
  access to out-of-bounds memory." );
	script_tag( name: "solution", value: "Update to version 3.27.8, 3.30.5, 4.0.4 or later." );
	script_xref( name: "URL", value: "https://hhvm.com/blog/2019/04/03/hhvm-4.0.4.html" );
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
if(version_is_less( version: version, test_version: "3.27.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.27.8", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.28", test_version2: "3.30.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.30.5", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0", test_version2: "4.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.4", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

