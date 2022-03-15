if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112072" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-09 09:12:51 +0200 (Mon, 09 Oct 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-13 13:46:00 +0000 (Fri, 13 Oct 2017)" );
	script_cve_id( "CVE-2014-8492" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Profile Builder Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/profile-builder/detected" );
	script_tag( name: "summary", value: "WordPress plugin Profile Builder is vulnerable to multiple cross-site scripting (XSS) vulnerabilities
      in assets/misc/fallback-page.php that allow remote attackers to inject arbitrary web script or HTML via the (1) site_name, (2) message, or (3) site_url parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Profile Builder plugin before version 2.0.3." );
	script_tag( name: "solution", value: "Update to version 2.0.3 or later." );
	script_xref( name: "URL", value: "https://g0blin.co.uk/cve-2014-8492/" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8239" );
	exit( 0 );
}
CPE = "cpe:/a:cozmoslabs:profile-builder";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

