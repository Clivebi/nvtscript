CPE = "cpe:/a:wp-buy:wp_content_copy_protection_%26_no_right_click";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146074" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-04 02:56:28 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-24 12:53:00 +0000 (Mon, 24 May 2021)" );
	script_cve_id( "CVE-2021-24188" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WP Content Copy Protection & No Right Click Plugin < 3.1.5 Arbitrary Plugin Install Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-content-copy-protector/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WP Content Copy Protection & No Right Click
  is prone to an arbitrary plugin install vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Low privileged users could use the AJAX action 'cp_plugins_do_button_job_later_callback'
  to install any plugin (including a specific version) from the WordPress repository, which helps
  attackers install vulnerable plugins and could lead to more critical vulnerabilities like RCE." );
	script_tag( name: "affected", value: "WordPress WP Content Copy Protection & No Right Click plugin prior to version 3.1.5." );
	script_tag( name: "solution", value: "Update to version 3.1.5 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-content-copy-protector/#developers" );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/74889e29-5349-43d1-baf5-1622493be90c" );
	exit( 0 );
}
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
if(version_is_less( version: version, test_version: "3.1.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

