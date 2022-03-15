CPE = "cpe:/a:phplist:phplist";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146211" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-02 06:49:40 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 23:07:00 +0000 (Wed, 03 Feb 2021)" );
	script_cve_id( "CVE-2020-35708", "CVE-2021-3188" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "phpList <= 3.6.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phplist_detect.sc" );
	script_mandatory_keys( "phplist/detected" );
	script_tag( name: "summary", value: "phpList is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-35708: SQL injection by admins who provide a crafted fourth line of a file to the
  'Config - Import Administrators' page

  - CVE-2021-3188: CSV injection, related to the email parameter, and /lists/admin/ exports" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "phpList version 3.6.3 and prior." );
	script_tag( name: "solution", value: "No known solution is available as of 02nd July, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://tufangungor.github.io/exploit/2020/12/15/phplist-3.5.9-sql-injection.html" );
	script_xref( name: "URL", value: "https://wehackmx.com/security-research/WeHackMX-2021-001/" );
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
if(version_is_less_equal( version: version, test_version: "3.6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

