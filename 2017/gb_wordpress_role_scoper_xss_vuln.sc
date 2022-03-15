if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112044" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-12 11:33:51 +0200 (Tue, 12 Sep 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:58:00 +0000 (Tue, 09 Oct 2018)" );
	script_cve_id( "CVE-2015-8353" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Role Scoper Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/role-scoper/detected" );
	script_tag( name: "summary", value: "WordPress plugin Role Scoper is vulnerable to cross-site scripting (XSS) resulting in
attackers being able to inject arbitrary web script or HTML via the object_name parameter in a rs-object_role_edit page to wp-admin/admin.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Role Scoper plugin version 1.3.66 and prior." );
	script_tag( name: "solution", value: "Update to version 1.3.67 or later." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/134600/WordPress-Role-Scoper-1.3.66-Cross-Site-Scripting.html" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/role-scoper/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:agapetry:role-scoper";
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
if(version_is_less( version: version, test_version: "1.3.67" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.67", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

