if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112045" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-12 11:23:51 +0200 (Tue, 12 Sep 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:58:00 +0000 (Tue, 09 Oct 2018)" );
	script_cve_id( "CVE-2015-8350" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Calls To Action Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/cta/detected" );
	script_tag( name: "summary", value: "WordPress plugin Calls To Action is vulnerable to cross-site scripting (XSS) resulting in
attackers being able to inject arbitrary web script or HTML via the (1) open-tab parameter in a wp_cta_global_settings action to wp-admin/edit.php or (2) wp-cta-variation-id parameter to ab-testing-call-to-action-example/." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Calls To Action plugin before 2.5.1." );
	script_tag( name: "solution", value: "Update to version 2.5.1 or later." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/134598/WordPress-Calls-To-Action-2.4.3-Cross-Site-Scripting.html" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/cta/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:inboundnow:cta";
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
if(version_is_less( version: version, test_version: "2.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.5.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

