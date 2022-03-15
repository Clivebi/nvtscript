CPE = "cpe:/a:contact_form_7_captcha_project:contact_form_7_captcha";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146626" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-03 11:19:15 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-27 17:27:00 +0000 (Fri, 27 Aug 2021)" );
	script_cve_id( "CVE-2021-24565" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Contact Form 7 Captcha Plugin < 0.0.9 CSRF/XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/contact-form-7-simple-recaptcha/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Contact Form 7 Captcha is prone to a
  cross-site request forgery (CSRF) and cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The plugin does not have any CSRF check in place when saving
  its settings, allowing attacker to make a logged in user with the manage_options change them.
  Furthermore, the settings are not escaped when output in attributes, leading to a stored XSS
  issue." );
	script_tag( name: "affected", value: "WordPress Contact Form 7 Captcha plugin prior to version 0.0.9." );
	script_tag( name: "solution", value: "Update to version 0.0.9 or later." );
	script_xref( name: "URL", value: "https://wpscan.com/vulnerability/97bfef5e-2ee0-491a-a931-4f44c83e5be0" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/contact-form-7-simple-recaptcha/#developers" );
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
if(version_is_less( version: version, test_version: "0.0.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.0.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

