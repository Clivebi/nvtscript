CPE = "cpe:/a:emrevona:wp-fastest-cache";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145836" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-28 03:22:40 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-06 16:55:00 +0000 (Thu, 06 May 2021)" );
	script_cve_id( "CVE-2021-20714" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress WP Fastest Cache Plugin < 0.9.1.7 Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-fastest-cache/detected" );
	script_tag( name: "summary", value: "The WordPress plugin WP Fastest Cache is prone to a directory
  traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Directory traversal vulnerability in WP Fastest Cache allows a
  remote attacker with administrator privileges to delete arbitrary files on the server via
  unspecified vectors." );
	script_tag( name: "impact", value: "Arbitrary files on the server may be deleted by a user with an
  administrative privilege." );
	script_tag( name: "affected", value: "WordPress WP Fastest Cache plugin through version 0.9.1.6." );
	script_tag( name: "solution", value: "Update to version 0.9.1.7 or later." );
	script_xref( name: "URL", value: "https://jvn.jp/en/jp/JVN35240327/index.html" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-fastest-cache/#developers" );
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
if(version_is_less( version: version, test_version: "0.9.1.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.1.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

