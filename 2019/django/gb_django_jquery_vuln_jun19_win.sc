CPE = "cpe:/a:djangoproject:django";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142509" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-26 06:11:17 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2019-11358" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Django jQuery Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_django_detect_win.sc" );
	script_mandatory_keys( "django/windows/detected" );
	script_tag( name: "summary", value: "Django is prone to a vulnerability in the bundled jQuery." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "jQuery before 3.4.0, mishandles 'jQuery.extend(true, {}, ...)' because of
  'Object.prototype' pollution. If an unsanitized source object contained an enumerable '__proto__' property, it
  could extend the native 'Object.prototype'." );
	script_tag( name: "affected", value: "Django versions 2.1 before 2.1.9 and 2.2 before 2.2.2." );
	script_tag( name: "solution", value: "Update to version 2.1.9, 2.2.2 or later." );
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

