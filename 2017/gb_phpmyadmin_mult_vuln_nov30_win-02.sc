CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112003" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-08-18 16:10:02 +0200 (Fri, 18 Aug 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_cve_id( "CVE-2014-8960", "CVE-2014-8961" );
	script_bugtraq_id( 71244, 71245 );
	script_name( "phpMyAdmin Multiple Vulnerabilities - 30-Nov-14 (Windows) (02)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to multiple cross-site scripting (XSS)
      and directory traversal vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "phpMyAdmin 4.1.x before 4.1.14.7 and 4.2.x before 4.2.12" );
	script_tag( name: "solution", value: "Update to version 4.1.14.7 or 4.2.12." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2014-15/" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2014-16/" );
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
if(IsMatchRegexp( vers, "^4\\.1\\." )){
	if(version_is_less( version: vers, test_version: "4.1.14.7" )){
		vuln = TRUE;
		fix = "4.1.14.7";
	}
}
if(IsMatchRegexp( vers, "^4\\.2\\." )){
	if(version_is_less( version: vers, test_version: "4.2.12" )){
		vuln = TRUE;
		fix = "4.2.12";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

