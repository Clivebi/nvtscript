CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108238" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-09-11 08:48:02 +0200 (Mon, 11 Sep 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-5339", "CVE-2012-5368" );
	script_bugtraq_id( 55925, 55939 );
	script_name( "phpMyAdmin 3.5.x < 3.5.3 Multiple Vulnerabilities (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2012-6/" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2012-7/" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to multiple cross-site scripting (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "phpMyAdmin 3.5.x before 3.5.3." );
	script_tag( name: "solution", value: "Update to version 3.5.3 or newer." );
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
if(IsMatchRegexp( vers, "^3\\.5\\." )){
	if(version_is_less( version: vers, test_version: "3.5.3" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.5.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

