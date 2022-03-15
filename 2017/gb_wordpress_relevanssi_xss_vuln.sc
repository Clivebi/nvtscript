if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106968" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-19 15:10:51 +0700 (Wed, 19 Jul 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-20 18:54:00 +0000 (Thu, 20 Jul 2017)" );
	script_cve_id( "CVE-2017-1000038" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Relevanssi Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/relevanssi/detected" );
	script_tag( name: "summary", value: "WordPress plugin Relevanssi is vulnerable to stored XSS resulting in
attacker being able to execute JavaScript on the affected site" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Relevanssi plugin version 3.5.7.1 and prior." );
	script_tag( name: "solution", value: "Update to version 3.5.8 or later." );
	script_xref( name: "URL", value: "https://security.dxw.com/advisories/stored-xss-in-relevanssi-could-allow-an-unauthenticated-attacker-to-do-almost-anything-an-admin-can-do/" );
	exit( 0 );
}
CPE = "cpe:/a:mikkosaari:relevanssi";
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
if(version_is_less( version: version, test_version: "3.5.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

