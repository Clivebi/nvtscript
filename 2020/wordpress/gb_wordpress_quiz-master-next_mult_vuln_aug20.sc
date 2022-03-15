if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112813" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-20 11:42:00 +0000 (Thu, 20 Aug 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-12 21:08:00 +0000 (Tue, 12 Jan 2021)" );
	script_cve_id( "CVE-2020-35949", "CVE-2020-35951" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Quiz And Survey Master Plugin < 7.0.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/quiz-master-next/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Quiz And Survey Master is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "If a quiz contained a file upload which was configured to only accept .txt files,
  an executable PHP file could be uploaded by setting the 'Content-Type' field to 'text/plain' to bypass the plugin's weak checks.
  This meant that unauthenticated users could upload arbitrary files, including PHP files, to a site and achieve remote code execution
  when there was a quiz enabled on the site that allowed file uploads as a response.

  Additionally Quiz and Survey Master provides file deletion functionality to remove any files that were uploaded during the quiz.
  The 'qsm_remove_file_fd_question' function is registered with a regular AJAX action and a nopriv AJAX action. This meant that the
  function could be triggered by unauthenticated users, which is to be expected due to the quizzes not requiring authentication.

  Unfortunately, there were no checks when verifying that the file_url supplied for file deletion was from a quiz or survey upload,
  so any file could be supplied and subsequently removed. This made it possible for attackers to delete important files like a site's wp-config.php file." );
	script_tag( name: "impact", value: "Successful exploitation would lead to complete site takeover and hosting account compromise amongst many other scenarios.

  Deleting the wp-config.php file would disable a site's database connection and allow an attacker to re-complete the installation procedures
  to connect their own database to a site's file system and regenerate a wp-config.php file. At that point they could use this access
  to infect other sites on the site's hosting account, or continue to use the site to infect site visitors." );
	script_tag( name: "affected", value: "WordPress Quiz And Survey Master plugin before version 7.0.1." );
	script_tag( name: "solution", value: "Update to version 7.0.1 or later." );
	script_xref( name: "URL", value: "https://www.wordfence.com/blog/2020/08/critical-vulnerabilities-patched-in-quiz-and-survey-master-plugin/" );
	exit( 0 );
}
CPE = "cpe:/a:expresstech:quiz-master-next";
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
if(version_is_less( version: version, test_version: "7.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

