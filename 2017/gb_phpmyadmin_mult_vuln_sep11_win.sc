CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108209" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-08-16 12:18:02 +0200 (Wed, 16 Aug 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-3591", "CVE-2011-3592" );
	script_name( "phpMyAdmin Multiple XSS Vulnerabilities Sep11 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2011-14/" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "phpMyAdmin versions 3.4.x before 3.4.5." );
	script_tag( name: "solution", value: "Update to version 3.4.5 or later." );
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
if(IsMatchRegexp( vers, "^3\\.4\\." )){
	if(version_is_less( version: vers, test_version: "3.4.5" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.4.5" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

