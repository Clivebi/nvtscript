CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108125" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)" );
	script_cve_id( "CVE-2016-6617", "CVE-2016-6608" );
	script_name( "phpMyAdmin SQL Injection and Multiple XSS Vulnerabilities Dec16 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to a SQL injection and multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple XSS vulnerabilities were found in the following areas:

  - database privilege check

  - Remove partitioning functionality

  An additional vulnerability was found in the export functionality:

  - a specially crafted database and/or table name can be used to trigger an SQL injection attack." );
	script_tag( name: "affected", value: "phpMyAdmin versions 4.6.x prior to 4.6.4." );
	script_tag( name: "solution", value: "Update to version 4.6.4 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^4\\.6\\." )){
	if(version_is_less( version: vers, test_version: "4.6.4" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "4.6.4" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

