if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108513" );
	script_version( "2021-05-28T07:06:21+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 07:06:21 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-12-12 07:54:53 +0100 (Wed, 12 Dec 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-22 14:10:00 +0000 (Mon, 22 Apr 2019)" );
	script_cve_id( "CVE-2018-19968", "CVE-2018-19970" );
	script_name( "phpMyAdmin 4.x < 4.8.4 Multiple Vulnerabilities - PMASA-2018-6, PMASA-2018-8 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2018-6/" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2018-8/" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to multiple security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "- A flaw has been found where an attacker can exploit phpMyAdmin to
  leak the contents of a local file. The attacker must have access to the phpMyAdmin Configuration Storage
  tables, although these can easily be created in any database to which the attacker has access. An attacker
  must have valid credentials to log in to phpMyAdmin. This vulnerability does not allow an attacker to
  circumvent the login system (CVE-2018-19968).

  - A Cross-Site Scripting vulnerability was found in the navigation tree, where an attacker can deliver a
  payload to a user through a specially-crafted database/table name (CVE-2018-19970)." );
	script_tag( name: "affected", value: "phpMyAdmin versions from at least 4.0 through 4.8.3." );
	script_tag( name: "solution", value: "Update to version 4.8.4 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "4.0", test_version2: "4.8.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.8.4", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

