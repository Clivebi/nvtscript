if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112794" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-30 08:47:00 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-28 19:15:00 +0000 (Mon, 28 Jun 2021)" );
	script_cve_id( "CVE-2020-24186" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress wpDiscuz Plugin 7.x < 7.0.5 Arbitrary File Upload Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wpdiscuz/detected" );
	script_tag( name: "summary", value: "The WordPress plugin wpDiscuz is prone to an arbitrary file upload vulnerability." );
	script_tag( name: "insight", value: "The wpDiscuz comments are intended to only allow image attachments.
  However, due to the file mime type detection functions that were used, the file type verification could
  easily be bypassed, allowing unauthenticated users the ability to upload any type of file, including PHP files." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to upload arbitrary PHP files
  and then access those files to trigger their execution on the server, achieving remote code execution.

  If exploited, this vulnerability then could allow an attacker to execute commands on your server and traverse your
  hosting account to further infect any sites hosted in the account with malicious code. This would effectively
  give the attacker complete control over every site on your server." );
	script_tag( name: "affected", value: "WordPress wpDiscuz plugin version 7.0.0 through 7.0.4." );
	script_tag( name: "solution", value: "Update to version 7.0.5 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wpdiscuz/#developers" );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/07/critical-arbitrary-file-upload-vulnerability-patched-in-wpdiscuz-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:gvectors:wpdiscuz";
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
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

