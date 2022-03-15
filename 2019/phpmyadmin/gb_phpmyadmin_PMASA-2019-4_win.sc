CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142500" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-11 04:26:01 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-14 04:29:00 +0000 (Fri, 14 Jun 2019)" );
	script_cve_id( "CVE-2019-12616" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "phpMyAdmin < 4.9.0 CSRF Vulnerability - PMASA-2019-4 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to a CSRF vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was found that allows an attacker to trigger a CSRF attack
  against a phpMyAdmin user. The attacker can trick the user, for instance through a broken <img> tag pointing at
  the victim's phpMyAdmin database, and the attacker can potentially deliver a payload (such as a specific INSERT
  or DELETE statement) through the victim." );
	script_tag( name: "affected", value: "phpMyAdmin prior to version 4.9.0." );
	script_tag( name: "solution", value: "Update to version 4.9.0 or later." );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2019-4/" );
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
if(version_is_less( version: version, test_version: "4.9.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9.0", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

