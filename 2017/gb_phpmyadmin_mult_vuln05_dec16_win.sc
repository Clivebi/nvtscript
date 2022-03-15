CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108132" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)" );
	script_cve_id( "CVE-2016-9866", "CVE-2016-9865", "CVE-2016-9864", "CVE-2016-9861", "CVE-2016-9860", "CVE-2016-9859", "CVE-2016-9858", "CVE-2016-9857", "CVE-2016-9856", "CVE-2016-9850", "CVE-2016-9849", "CVE-2016-9848", "CVE-2016-9847" );
	script_name( "phpMyAdmin Multiple Security Vulnerabilities - 04 - Dec16 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to multiple security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "phpMyAdmin 4.6.x prior to 4.6.5, 4.4.x prior to 4.4.15.9, and 4.0.x prior to 4.0.10.18." );
	script_tag( name: "solution", value: "Update to version 4.6.5, 4.4.15.9 or 4.0.10.18." );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(IsMatchRegexp( vers, "^4\\.0\\." )){
	if(version_is_less( version: vers, test_version: "4.0.10.18" )){
		vuln = TRUE;
		fix = "4.0.10.18";
	}
}
if(IsMatchRegexp( vers, "^4\\.4\\." )){
	if(version_is_less( version: vers, test_version: "4.4.15.9" )){
		vuln = TRUE;
		fix = "4.4.15.9";
	}
}
if(IsMatchRegexp( vers, "^4\\.6\\." )){
	if(version_is_less( version: vers, test_version: "4.6.5" )){
		vuln = TRUE;
		fix = "4.6.5";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

