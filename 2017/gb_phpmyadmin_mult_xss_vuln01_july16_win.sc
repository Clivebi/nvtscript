CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106491" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-03 09:57:21 +0700 (Tue, 03 Jan 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)" );
	script_cve_id( "CVE-2016-6615", "CVE-2016-6616" );
	script_bugtraq_id( 95041 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "phpMyAdmin SQL Injection and Multiple XSS Vulnerabilities July16 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to a SQL injection and multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks the banner." );
	script_tag( name: "insight", value: "Multiple XSS vulnerabilities were found in the following areas:

  - Navigation pane and database/table hiding feature. A specially-crafted database name can be used to trigger
an XSS attack.

  - The 'Tracking' feature. A specially-crafted query can be used to trigger an XSS attack.

  - GIS visualization feature.

An additional vulnerability was found in the 'User group' and 'Designer' features:

  - a user can execute an SQL injection attack against the account of the control user." );
	script_tag( name: "affected", value: "phpMyAdmin versions 4.4.x prior to 4.4.15.8 and 4.6.x prior to 4.6.4." );
	script_tag( name: "solution", value: "Update to version 4.4.15.8 or 4.6.4." );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2016-38/" );
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
if(IsMatchRegexp( version, "^4\\.4\\." )){
	if(version_is_less( version: version, test_version: "4.4.15.8" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.4.15.8" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^4\\.6\\." )){
	if(version_is_less( version: version, test_version: "4.6.4" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.6.4" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

