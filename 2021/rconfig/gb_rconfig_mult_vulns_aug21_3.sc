CPE = "cpe:/a:rconfig:rconfig";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118160" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-23 11:46:09 +0200 (Mon, 23 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-23 19:32:00 +0000 (Mon, 23 Aug 2021)" );
	script_cve_id( "CVE-2020-27464", "CVE-2020-27466" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "rConfig <= 3.9.6 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rconfig_detect.sc" );
	script_mandatory_keys( "rconfig/detected" );
	script_tag( name: "summary", value: "rConfig is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-27464: An insecure update feature in the '/updater.php' component allows attackers
  to execute arbitrary code via a crafted ZIP file.

  - CVE-2020-27466: An arbitrary file write vulnerability in 'lib/AjaxHandlers/ajaxEditTemplate.php'
  allows attackers to execute arbitrary code via a crafted file." );
	script_tag( name: "affected", value: "rConfig version 3.9.6 and probably prior." );
	script_tag( name: "solution", value: "No known solution is available as of 23rd August, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://www.rconfig.com/downloads/v3-release-notes" );
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
if(version_is_less_equal( version: version, test_version: "3.9.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

