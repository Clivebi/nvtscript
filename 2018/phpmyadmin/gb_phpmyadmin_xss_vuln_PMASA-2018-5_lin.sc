if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113255" );
	script_version( "2021-05-28T07:06:21+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 07:06:21 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-08-29 11:16:18 +0200 (Wed, 29 Aug 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-26 01:11:00 +0000 (Fri, 26 Oct 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-15605" );
	script_name( "phpMyAdmin <= 4.8.2 XSS Vulnerability - PMASA-2018-5 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to an authenticated Cross-Site Scripting (XSS) Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An authenticated attacker could trick a user into importing a specially crafted file,
  resulting in the attacker gaining control over the user's account." );
	script_tag( name: "affected", value: "phpMyAdmin through version 4.8.2." );
	script_tag( name: "solution", value: "Update to version 4.8.3." );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2018-5/" );
	exit( 0 );
}
CPE = "cpe:/a:phpmyadmin:phpmyadmin";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.8.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.3" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

