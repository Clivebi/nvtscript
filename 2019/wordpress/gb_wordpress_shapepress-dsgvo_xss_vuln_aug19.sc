if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113507" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-11 12:10:56 +0000 (Wed, 11 Sep 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-03 19:28:00 +0000 (Tue, 03 Sep 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-15777" );
	script_name( "WordPress WP DSGVO Tools Plugin < 2.2.19 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/shapepress-dsgvo/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WP DSGVO Tools is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is exploitable via
  wp-admin/admin-ajax.php?action=admin-common-settings&admin_email=." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker
  to inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "WordPress WP DSGVO Tools plugin through version 2.2.18." );
	script_tag( name: "solution", value: "Update to version 2.2.19 or later." );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9850" );
	script_xref( name: "URL", value: "https://www.pluginvulnerabilities.com/2019/08/22/gdpr-plugins-for-wordpress-continue-to-be-insecure/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/shapepress-dsgvo/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:legalweb:shapepress-dsgvo";
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
if(version_is_less( version: version, test_version: "2.2.19" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.19", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

