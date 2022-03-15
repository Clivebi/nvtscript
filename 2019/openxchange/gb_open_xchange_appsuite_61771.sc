CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142234" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-04-09 13:12:16 +0000 (Tue, 09 Apr 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-7159" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Open-Xchange (OX) AppSuite Information Disclosure Vulnerability (Bug ID 61771)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	script_tag( name: "summary", value: "Open-Xchange (OX) AppSuite is prone to an information exposure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The 'oxsysreport' tool failed to sanitize custom configuration parameters that could contain credentials like API keys." );
	script_tag( name: "affected", value: "All Open-Xchange AppSuite versions before 7.6.3-rev44, 7.8.3 before rev53, 7.8.4 before rev51, 7.10.0 before rev25 and 7.10.1 before rev7." );
	script_tag( name: "solution", value: "Update to version 7.6.3-rev44, 7.8.3-rev53, 7.8.4-rev51, 7.10.0-rev25 or 7.10.1-rev7 respectively." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/152404/Open-Xchange-AppSuite-7.10.1-Information-Disclosure-Improper-Access-Control.html" );
	script_xref( name: "URL", value: "https://seclists.org/fulldisclosure/2019/Apr/2" );
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
if(!revision = get_kb_item( "open_xchange_appsuite/" + port + "/revision" )){
	exit( 0 );
}
version += "." + revision;
if(version_is_less( version: version, test_version: "7.6.3.44" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.6.3.44", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.7", test_version2: "7.8.3.52" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.8.3.53", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.8.4", test_version2: "7.8.4.50" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.8.4.51", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.10.0", test_version2: "7.10.0.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.10.0.25", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.10.1", test_version2: "7.10.1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.10.1.7", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

