if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112606" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-12 10:27:00 +0000 (Fri, 12 Jul 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-31 08:15:00 +0000 (Wed, 31 Jul 2019)" );
	script_cve_id( "CVE-2019-5972", "CVE-2019-5973" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Online Lesson Booking Plugin < 0.8.7 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/online-lesson-booking-system/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Online Lesson Booking is prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "An arbitrary script may be executed on the web browser of the user with the administrative privilege. - CVE-2019-5972

  If a user with the administrative privilege views a malicious page while logged in, unintended operations may be performed. - CVE-2019-5973" );
	script_tag( name: "affected", value: "WordPress Online Lesson Booking plugin before version 0.8.7." );
	script_tag( name: "solution", value: "Update to version 0.8.7 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/online-lesson-booking-system/#developers" );
	script_xref( name: "URL", value: "https://jvn.jp/en/jp/JVN96988995/index.html" );
	exit( 0 );
}
CPE = "cpe:/a:sukimalab:online-lesson-booking-system";
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
if(version_is_less( version: version, test_version: "0.8.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.8.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

