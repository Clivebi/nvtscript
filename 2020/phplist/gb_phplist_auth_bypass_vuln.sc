CPE = "cpe:/a:phplist:phplist";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143486" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-10 06:51:12 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-06 17:25:00 +0000 (Thu, 06 Feb 2020)" );
	script_cve_id( "CVE-2020-8547" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "phpList < 3.5.1 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phplist_detect.sc" );
	script_mandatory_keys( "phplist/detected" );
	script_tag( name: "summary", value: "phpList is prone to an authentication bypass vulnerability." );
	script_tag( name: "insight", value: "phpList allows type juggling for admin login bypass because == is used instead
  of === for password hashes, which mishandles hashes that begin with 0e followed by exclusively numerical
  characters." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "phpList version 3.5.0 and probably prior." );
	script_tag( name: "solution", value: "Update to version 3.5.1 or later." );
	script_xref( name: "URL", value: "https://www.phplist.org/newslist/phplist-3-5-1-release-notes/" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/47989" );
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
if(version_is_less( version: version, test_version: "3.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

