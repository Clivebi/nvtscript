if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112529" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-05 11:34:00 +0100 (Tue, 05 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-07 20:29:00 +0000 (Thu, 07 Mar 2019)" );
	script_cve_id( "CVE-2019-9568", "CVE-2019-9567" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Forminator Plugin < 1.6 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/forminator/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Forminator is prone to a persistent cross-site
  scripting and blind SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Forminator plugin before version 1.6." );
	script_tag( name: "solution", value: "Update to version 1.6 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/forminator/#developers" );
	script_xref( name: "URL", value: "https://security-consulting.icu/blog/2019/02/wordpress-forminator-persistent-xss-blind-sql-injection/" );
	script_xref( name: "URL", value: "https://lists.openwall.net/full-disclosure/2019/02/05/4" );
	exit( 0 );
}
CPE = "cpe:/a:wpmudev:forminator";
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
if(version_is_less( version: version, test_version: "1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

