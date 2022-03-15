if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113197" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-05-24 16:32:39 +0200 (Thu, 24 May 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-26 17:03:00 +0000 (Tue, 26 Jun 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-11366" );
	script_name( "WordPress Loginizer Plugin Stored XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/loginizer/detected" );
	script_tag( name: "summary", value: "WordPress Loginizer plugin is prone to a stored Cross-Site Scripting (XSS) Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The problem exists due to mishandled logging." );
	script_tag( name: "affected", value: "Loginizer versions 1.3.8 through 1.3.9." );
	script_tag( name: "solution", value: "Update to version 1.4.0." );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9088" );
	script_xref( name: "URL", value: "https://blog.dewhurstsecurity.com/2018/05/22/loginizer-wordpress-plugin-xss-vulnerability.html" );
	script_xref( name: "URL", value: "https://plugins.trac.wordpress.org/changeset/1878502/loginizer" );
	exit( 0 );
}
CPE = "cpe:/a:raj_kothari:loginizer";
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
if(version_in_range( version: version, test_version: "1.3.8", test_version2: "1.3.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.4.0", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

