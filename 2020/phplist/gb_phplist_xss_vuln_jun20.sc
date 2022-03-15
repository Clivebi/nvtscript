if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113698" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-08 09:28:04 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-27 12:15:00 +0000 (Thu, 27 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-13827" );
	script_name( "phpList < 3.5.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phplist_detect.sc" );
	script_mandatory_keys( "phplist/detected" );
	script_tag( name: "summary", value: "phpList is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is exploitable
  via /lists/admin/user.php and /lists/admin/users.php" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "phpList through version 3.5.3." );
	script_tag( name: "solution", value: "Update to version 3.5.4." );
	script_xref( name: "URL", value: "https://www.phplist.org/newslist/phplist-3-5-4-release-notes/" );
	exit( 0 );
}
CPE = "cpe:/a:phplist:phplist";
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
if(version_is_less( version: version, test_version: "3.5.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.4", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

