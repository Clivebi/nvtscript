CPE = "cpe:/a:djangoproject:django";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146098" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-06-09 07:13:21 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-17 15:49:00 +0000 (Thu, 17 Jun 2021)" );
	script_cve_id( "CVE-2021-33203", "CVE-2021-33571" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Django < 2.2.24, 3.0 < 3.1.12, 3.2 < 3.2.4 Multiple Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_django_detect_win.sc" );
	script_mandatory_keys( "django/windows/detected" );
	script_tag( name: "summary", value: "Django is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-33203: Potential directory traversal via admindocs

  - CVE-2021-33571: Possible indeterminate SSRF, RFI, and LFI attacks since validators accepted
  leading zeros in IPv4 addresses" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Django prior to version 2.2.24, 3.0 through 3.1.11 and 3.2
  through 3.2.3." );
	script_tag( name: "solution", value: "Update to version 2.2.24, 3.1.12, 3.2.4 or later." );
	script_xref( name: "URL", value: "https://www.djangoproject.com/weblog/2021/jun/02/security-releases/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.2.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.24", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.0.0", test_version2: "3.1.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.12", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.4", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

