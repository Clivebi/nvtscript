CPE = "cpe:/a:djangoproject:django";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142506" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-26 05:46:56 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-12 17:29:00 +0000 (Wed, 12 Jun 2019)" );
	script_cve_id( "CVE-2019-12308" );
	script_bugtraq_id( 108559 );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Django AdminURLFieldWidget XSS Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_django_detect_lin.sc" );
	script_mandatory_keys( "Django/Linux/Ver" );
	script_tag( name: "summary", value: "Django is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The clickable 'Current URL' link generated by 'AdminURLFieldWidget' displays
  the provided value without validating it as a safe URL. Thus, an unvalidated value stored in the database, or a
  value provided as a URL query parameter payload, could result in a clickable JavaScript link." );
	script_tag( name: "affected", value: "Django versions 1.11 before 1.11.21, 2.1 before 2.1.9 and 2.2 before 2.2.2." );
	script_tag( name: "solution", value: "Update to version 1.11.21, 2.1.9, 2.2.2 or later." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2019/06/03/2" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "1.11", test_version2: "1.11.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.11.21", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.1", test_version2: "2.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.9", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.2", test_version2: "2.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.2", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

