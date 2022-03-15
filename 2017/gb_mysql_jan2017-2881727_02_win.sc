if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809865" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_cve_id( "CVE-2017-3238", "CVE-2017-3318", "CVE-2017-3291", "CVE-2017-3317", "CVE-2017-3258", "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3244", "CVE-2017-3265" );
	script_bugtraq_id( 95571, 95560, 95491, 95527, 95565, 95588, 95501, 95585, 95520 );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-01-18 18:37:01 +0530 (Wed, 18 Jan 2017)" );
	script_name( "Oracle Mysql Security Updates (jan2017-2881727) 02 - Windows" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to: multiple
  unspecified errors in sub components 'Error Handling', 'Logging', 'MyISAM',
  'Packaging', 'Optimizer', 'DML' and 'DDL'." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote to have an impact on availability,
  confidentiality and integrity." );
	script_tag( name: "affected", value: "Oracle MySQL version
  5.5.53 and earlier, 5.6.34 and earlier, 5.7.16 and earlier on Windows" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html" );
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
if(IsMatchRegexp( vers, "^5\\." )){
	if(version_in_range( version: vers, test_version: "5.5", test_version2: "5.5.53" ) || version_in_range( version: vers, test_version: "5.6", test_version2: "5.6.34" ) || version_in_range( version: vers, test_version: "5.7", test_version2: "5.7.16" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

