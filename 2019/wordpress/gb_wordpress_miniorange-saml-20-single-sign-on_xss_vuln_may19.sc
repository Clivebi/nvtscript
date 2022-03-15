if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112436" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-27 11:25:00 +0200 (Thu, 27 Jun 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-27 11:15:00 +0000 (Thu, 27 Jun 2019)" );
	script_cve_id( "CVE-2019-12346" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress miniOrange SAML SP Single Sign On Plugin <= 4.8.72 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/miniorange-saml-20-single-sign-on/detected" );
	script_tag( name: "summary", value: "The WordPress plugin miniOrange SAML SP Single Sign On is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to inject malicious content into an affected site." );
	script_tag( name: "affected", value: "WordPress miniOrange SAML SP Single Sign On plugin through version 4.8.72." );
	script_tag( name: "solution", value: "Update to version 4.8.73 or later." );
	script_xref( name: "URL", value: "https://zeroauth.ltd/blog/2019/05/27/cve-2019-12346-miniorange-saml-sp-single-sign-on-wordpress-plugin-xss/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/miniorange-saml-20-single-sign-on/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:miniorange:miniorange-saml-20-single-sign-on";
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
if(version_is_less( version: version, test_version: "4.8.73" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.73", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

