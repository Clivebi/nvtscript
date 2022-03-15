CPE = "cpe:/a:rconfig:rconfig";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118159" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-23 11:46:09 +0200 (Mon, 23 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-24 15:21:00 +0000 (Tue, 24 Aug 2021)" );
	script_cve_id( "CVE-2020-25351", "CVE-2020-25352", "CVE-2020-25353", "CVE-2020-25359" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "rConfig < 3.9.6 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rconfig_detect.sc" );
	script_mandatory_keys( "rconfig/detected" );
	script_tag( name: "summary", value: "rConfig is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-25351: An information disclosure vulnerability allows remote authenticated attackers
  to read files on the system via a crafted request sent to the '/lib/crud/configcompare.crud.php'
  script.

  - CVE-2020-25352: A stored cross-site scripting (XSS) vulnerability in the '/devices.php' function
  allows remote attackers to perform arbitrary Javascript execution through entering a crafted
  payload into the 'Model' field then saving.

  - CVE-2020-25353: A server-side request forgery (SSRF) vulnerability allows remote authenticated
  attackers to open a connection to the machine via the deviceIpAddr and connPort parameters.

  - CVE-2020-25359: An arbitrary file deletion vulnerability gives attackers the ability to send a
  crafted request to /lib/ajaxHandlers/ajaxDeleteAllLoggingFiles.php by specifying a path in the
  'path' parameter and an extension in the 'ext' parameter and delete all the files with that
  extension in that path." );
	script_tag( name: "affected", value: "rConfig prior to version 3.9.6." );
	script_tag( name: "solution", value: "Update to version 3.9.6 or later" );
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
if(version_is_less( version: version, test_version: "3.9.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

