CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112015" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-08-21 11:38:02 +0200 (Mon, 21 Aug 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2014-7217" );
	script_bugtraq_id( 70252 );
	script_name( "phpMyAdmin Multiple Cross-Site Scripting Vulnerabilities - Oct14 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2014-11/" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "phpMyAdmin 4.2.x prior to 4.2.9.1, 4.1.x prior to 4.1.14.5, and 4.0.x prior to 4.0.10.4." );
	script_tag( name: "solution", value: "Update to version 4.2.9.1, 4.1.14.5 or 4.0.10.4." );
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
if(IsMatchRegexp( vers, "^4\\.0\\." )){
	if(version_is_less( version: vers, test_version: "4.0.10.4" )){
		vuln = TRUE;
		fix = "4.0.10.4";
	}
}
if(IsMatchRegexp( vers, "^4\\.1\\." )){
	if(version_is_less( version: vers, test_version: "4.1.14.5" )){
		vuln = TRUE;
		fix = "4.1.14.5";
	}
}
if(IsMatchRegexp( vers, "^4\\.2\\." )){
	if(version_is_less( version: vers, test_version: "4.2.9.1" )){
		vuln = TRUE;
		fix = "4.2.9.1";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

