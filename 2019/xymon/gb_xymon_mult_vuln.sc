CPE = "cpe:/a:xymon:xymon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142822" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-29 08:12:03 +0000 (Thu, 29 Aug 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-27 17:36:00 +0000 (Thu, 27 Aug 2020)" );
	script_cve_id( "CVE-2019-13451", "CVE-2019-13452", "CVE-2019-13455", "CVE-2019-13473", "CVE-2019-13474", "CVE-2019-13484", "CVE-2019-13485", "CVE-2019-13486" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Xymon < 4.3.29 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xymon_monitor_detect.sc" );
	script_mandatory_keys( "xymon/detected" );
	script_tag( name: "summary", value: "Xymon is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Xymon is prone to multiple vulnerabilities:

  - CVE-2019-13451, CVE-2019-13452, CVE-2019-13455, CVE-2019-13473, CVE-2019-13484, CVE-2019-13485,
  CVE-2019-13486: Multiple buffer overflow vulnerabilities

  - CVE-2019-13474: XSS vulnerability in the csvinfo CGI script" );
	script_tag( name: "affected", value: "Xymon prior to version 4.3.29." );
	script_tag( name: "solution", value: "Update to version 4.3.29 or later." );
	script_xref( name: "URL", value: "https://sourceforge.net/projects/xymon/files/Xymon/4.3.29/" );
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
if(version_is_less( version: version, test_version: "4.3.29" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.29", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

