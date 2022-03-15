if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112530" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-06 10:18:00 +0100 (Wed, 06 Mar 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-15 16:01:00 +0000 (Tue, 15 Jan 2019)" );
	script_cve_id( "CVE-2018-20368" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "WordPress Master Slider Plugin <= 3.5.8 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/master-slider/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Master Slider is prone to a persistent cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Master Slider plugin through version 3.5.8." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/master-slider/#developers" );
	script_xref( name: "URL", value: "https://www.vulnerability-lab.com/get_content.php?id=2158" );
	exit( 0 );
}
CPE = "cpe:/a:averta:master-slider";
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
if(version_is_less_equal( version: version, test_version: "3.5.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "NoneAvailable", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

