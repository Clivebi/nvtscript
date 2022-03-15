if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112094" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-26 13:35:51 +0200 (Thu, 26 Oct 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-14 22:08:00 +0000 (Tue, 14 Nov 2017)" );
	script_cve_id( "CVE-2017-15863" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress No External Links Plugin XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-noexternallinks/detected" );
	script_tag( name: "summary", value: "Cross-Site Scripting (XSS) exists in the No External Links plugin via the date1 or date2 parameter to wp-admin/options-general.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress No External Links plugin before 3.5.19." );
	script_tag( name: "solution", value: "Update to version 3.5.19 or later." );
	script_xref( name: "URL", value: "http://lists.openwall.net/full-disclosure/2017/06/02/3" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-noexternallinks/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:steamerdevelopment:wp-noexternallinks";
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
if(version_is_less( version: version, test_version: "3.5.19" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.19", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

