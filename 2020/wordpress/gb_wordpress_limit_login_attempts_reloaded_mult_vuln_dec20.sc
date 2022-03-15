CPE = "cpe:/a:limitloginattempts:limit_login_attempts_reloaded";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145089" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-12-23 04:13:12 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-22 20:01:00 +0000 (Tue, 22 Dec 2020)" );
	script_cve_id( "CVE-2020-35589", "CVE-2020-35590" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Limit Login Attempts Reloaded Plugin < 2.17.4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/contact-form-7/detected" );
	script_tag( name: "summary", value: "WordPress Limit Login Attempts Reloaded plugin is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Cross-site scripting (XSS) in wp-admin/options-general.php?page=limit-login-attempts&tab= (CVE-2020-35589)

  - Bypass of (per IP address) rate limits because the X-Forwarded-For header can be forged (CVE-2020-35590)" );
	script_tag( name: "impact", value: "- A malicious user can cause an administrator user to supply dangerous content
  to the vulnerable page, which is then reflected back to the user and executed by the web browser. The most
  common mechanism for delivering malicious content is to include it as a parameter in a URL that is posted
  publicly or e-mailed directly to victims. (CVE-2020-35589)

  - When the plugin is configured to accept an arbitrary header for the client source IP address, a malicious user
    is not limited to perform a brute force attack, because the client IP header accepts any arbitrary string.
    When randomizing the header input, the login count does not ever reach the maximum allowed retries. (CVE-2020-35590)" );
	script_tag( name: "affected", value: "WordPress Limit Login Attempts Reloaded plugin version 2.17.3 and prior." );
	script_tag( name: "solution", value: "Update to version 2.17.4 or later." );
	script_xref( name: "URL", value: "https://n4nj0.github.io/advisories/wordpress-plugin-limit-login-attempts-reloaded/" );
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
if(version_is_less( version: version, test_version: "2.17.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.17.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

