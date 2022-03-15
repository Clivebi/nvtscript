CPE = "cpe:/a:livemeshelementor:addons_for_elementor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145953" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-17 04:45:15 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-11 15:17:00 +0000 (Tue, 11 May 2021)" );
	script_cve_id( "CVE-2021-24260" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Livemesh Addons for Elementor Plugin < 6.8 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/addons-for-elementor/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Livemesh Addons for Elementor is prone to
  a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Livemesh Addons for Elementor plugin has several widgets that
  are vulnerable to stored XSS by lower-privileged users such as contributors, all via a similar method." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to
  inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "WordPress Livemesh Addons for Elementor plugin prior to version
  6.8." );
	script_tag( name: "solution", value: "Update to version 6.8 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/fa6c7c7c-1027-4fa9-bb55-07ae2bb7f021" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/addons-for-elementor/#developers" );
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
if(version_is_less( version: version, test_version: "6.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

