if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810884" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-3305" );
	script_bugtraq_id( 97023 );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-19 16:45:28 +0530 (Wed, 19 Apr 2017)" );
	script_name( "Oracle Mysql Security Updates (apr2017-3236618) 03 - Windows" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an incorrect
  implementation or enforcement of 'ssl-mode=REQUIRED' in MySQL." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to bypass certain security restrictions and perform
  unauthorized actions by conducting a man-in-the-middle attack. This may lead to
  other attacks also." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.5.54 and earlier,
  5.6.35 and earlier on Windows" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:oracle:mysql";
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "5.5", test_version2: "5.5.54" ) || version_in_range( version: vers, test_version: "5.6", test_version2: "5.6.35" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

