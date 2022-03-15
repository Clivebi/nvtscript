CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141949" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-31 16:55:25 +0700 (Thu, 31 Jan 2019)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-27 14:29:00 +0000 (Wed, 27 Mar 2019)" );
	script_cve_id( "CVE-2018-13103", "CVE-2018-13104" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Open-Xchange (OX) AppSuite Multiple Vulnerabilities (58742, 56457)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	script_tag( name: "summary", value: "Open-Xchange (OX AppSuite is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Open-Xchange (OX AppSuite is prone to multiple vulnerabilities:

  - Cross-Site Scripting (BugID: 58742)

  - Server-Side Request Forgery (BugID: 56457)" );
	script_tag( name: "affected", value: "OX AppSuite versions 7.8.4 and prior." );
	script_tag( name: "solution", value: "Update to version 7.6.3-rev41, 7.8.3-rev50, 7.8.4-rev39 or later." );
	script_xref( name: "URL", value: "https://seclists.org/fulldisclosure/2019/Jan/46" );
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
if(!revision = get_kb_item( "open_xchange_appsuite/" + port + "/revision" )){
	exit( 0 );
}
version += "." + revision;
if(version_is_less( version: version, test_version: "7.6.3.41" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.6.3.41" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.8", test_version2: "7.8.3.49" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.8.3.50" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.8.4", test_version2: "7.8.4.38" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.8.4.39" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

