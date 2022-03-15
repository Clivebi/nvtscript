if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112502" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-28 14:49:12 +0100 (Mon, 28 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-28 15:55:00 +0000 (Mon, 28 Jan 2019)" );
	script_cve_id( "CVE-2019-6798" );
	script_name( "phpMyAdmin 4.5.0 <= 4.8.4 SQL Injection Vulnerability - PMASA-2019-2 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to an SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was reported where a specially crafted username
  can be used to trigger an SQL injection attack through the designer feature." );
	script_tag( name: "affected", value: "phpMyAdmin versions 4.5.0 through 4.8.4." );
	script_tag( name: "solution", value: "Update to version 4.8.5." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2019-2/" );
	exit( 0 );
}
CPE = "cpe:/a:phpmyadmin:phpmyadmin";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "4.5.0", test_version2: "4.8.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.8.5", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

