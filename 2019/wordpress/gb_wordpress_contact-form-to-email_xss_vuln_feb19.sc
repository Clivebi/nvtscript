if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112537" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-18 10:18:00 +0100 (Mon, 18 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 13:32:00 +0000 (Tue, 12 Mar 2019)" );
	script_cve_id( "CVE-2019-9646" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Contact Form Email Plugin < 1.2.66 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/contact-form-to-email/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Contact Form Email is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "affected", value: "WordPress Contact Form Email plugin before version 1.2.66." );
	script_tag( name: "solution", value: "Update to version 1.2.66 or later." );
	script_xref( name: "URL", value: "https://lists.openwall.net/full-disclosure/2019/02/05/7" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/contact-form-to-email/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:codepeople:contact-form-to-email";
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
if(version_is_less( version: version, test_version: "1.2.66" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.66", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

