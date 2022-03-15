if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113733" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-28 09:35:51 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 18:18:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-5611" );
	script_name( "WordPress Social Rocket Plugin < 1.2.10 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/social-rocket/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Social rocket is prone to a
  cross-site request forgery (CSRF) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  perform actions in the context of another user." );
	script_tag( name: "affected", value: "WordPress Social Rocket plugin through version 1.2.9." );
	script_tag( name: "solution", value: "Update to version 1.2.10." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/social-rocket/#developers" );
	script_xref( name: "URL", value: "https://jvn.jp/en/jp/JVN05502028/index.html" );
	exit( 0 );
}
CPE = "cpe:/a:wpsocialrocket:social_sharing";
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
if(version_is_less( version: version, test_version: "1.2.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.10", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

