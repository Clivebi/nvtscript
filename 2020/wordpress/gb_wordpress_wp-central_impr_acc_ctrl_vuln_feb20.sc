if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112703" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-25 10:09:00 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-19 21:30:00 +0000 (Wed, 19 Feb 2020)" );
	script_cve_id( "CVE-2020-9043" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress wpCentral Plugin < 1.5.1 Improper Access Control Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wp-central/detected" );
	script_tag( name: "summary", value: "The WordPress plugin wpCentral is prone to an improper access control vulnerability." );
	script_tag( name: "insight", value: "The flaw allows anybody to escalate their privileges to those of an administrator,
  as long as subscriber-level registration was enabled on a given WordPress site with the vulnerable plugin installed.

  The flaw also allowed for remote control of the site via the wpCentral administrative dashboard." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability would allow an authenticated remote attacker
  to escalate his privileges to those of an administrator and remotely control the affected site." );
	script_tag( name: "affected", value: "WordPress wpCentral plugin before version 1.5.1." );
	script_tag( name: "solution", value: "Update to version 1.5.1 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-central/#developers" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/10074" );
	exit( 0 );
}
CPE = "cpe:/a:wpcentral:wpcentral";
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
if(version_is_less( version: version, test_version: "1.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

