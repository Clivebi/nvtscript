if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117034" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-11-10 10:48:54 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-07 21:26:00 +0000 (Thu, 07 Jan 2021)" );
	script_cve_id( "CVE-2020-36155", "CVE-2020-36156", "CVE-2020-36157" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Ultimate Member Plugin <= 2.1.11 Multiple Privilege Escalation Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/ultimate-member/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Ultimate Member is prone to multiple
  critical privilege escalation vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following flaws exist:

  - unauthenticated privilege escalation via User Meta (CVE-2020-36155)

  - unauthenticated privilege escalation via User Roles (CVE-2020-36157)

  - authenticated privilege escalation via Profile Update (CVE-2020-36156)" );
	script_tag( name: "impact", value: "Successful exploitation would allow originally unauthenticated users
  to escalate their privileges with some conditions. Once an attacker has elevated access to a WordPress
  site, they can potentially take over the entire and further infect the site with malware." );
	script_tag( name: "affected", value: "WordPress Ultimate Member plugin through version 2.1.11." );
	script_tag( name: "solution", value: "Update to version 2.1.12 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ultimate-member/#developers" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/11/critical-privilege-escalation-vulnerabilities-affect-100k-sites-using-ultimate-member-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:ultimatemember:ultimate-member";
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
if(version_is_less_equal( version: version, test_version: "2.1.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.12", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

