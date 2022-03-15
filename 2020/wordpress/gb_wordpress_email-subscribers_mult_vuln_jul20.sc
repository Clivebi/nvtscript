if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112782" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-21 07:25:00 +0000 (Tue, 21 Jul 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-21 18:55:00 +0000 (Tue, 21 Jul 2020)" );
	script_cve_id( "CVE-2020-5767", "CVE-2020-5768" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Email Subscribers Plugin < 4.5.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/email-subscribers/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Email Subscribers & Newsletters is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Cross-site Request Forgery in send_test_email()

  - Authenticated SQL injection in es_newsletters_settings_callback()" );
	script_tag( name: "impact", value: "Successful exploitation of these vulnerabilities would allow an attacker
  to send forged emails by tricking legitimate users into clicking a crafted link or disclose potentially sensitive information from the WordPress database." );
	script_tag( name: "affected", value: "WordPress Email Subscribers & Newsletters plugin before version 4.5.1." );
	script_tag( name: "solution", value: "Update to version 4.5.1 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/email-subscribers/#developers" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/research/tra-2020-44-0" );
	exit( 0 );
}
CPE = "cpe:/a:icegram:email-subscribers";
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
if(version_is_less( version: version, test_version: "4.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

