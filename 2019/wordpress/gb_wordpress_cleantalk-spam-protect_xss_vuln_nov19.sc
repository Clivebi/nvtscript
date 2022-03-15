if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113568" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-11-15 12:59:15 +0000 (Fri, 15 Nov 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-18 14:52:00 +0000 (Mon, 18 Nov 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-17515" );
	script_name( "WordPress CleanTalk Plugin < 5.127.4 Cross-Site Scripting (XSS) Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/cleantalk-spam-protect/detected" );
	script_tag( name: "summary", value: "The WordPress CleanTalk plugin is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability resides within inc/cleantalk-users.php
  and inc/cleantalk-comments.php." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to inject
  arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "WordPress CleanTalk plugin through version 5.127.3." );
	script_tag( name: "solution", value: "Update to version 5.127.4 or later." );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/9949" );
	script_xref( name: "URL", value: "https://plugins.trac.wordpress.org/changeset/2172333" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/cleantalk-spam-protect/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:cleantalk:cleantalk-spam-protect";
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
if(version_is_less( version: version, test_version: "5.127.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.127.4", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );
