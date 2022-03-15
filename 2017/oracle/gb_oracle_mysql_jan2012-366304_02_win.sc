if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812344" );
	script_version( "2021-02-10T08:19:07+0000" );
	script_cve_id( "CVE-2012-0486", "CVE-2012-0487", "CVE-2012-0488", "CVE-2012-0489", "CVE-2012-0117", "CVE-2012-0495", "CVE-2012-0494", "CVE-2012-0496", "CVE-2012-0491", "CVE-2012-0493" );
	script_bugtraq_id( 51514, 51503, 51506, 51510, 51521, 51522, 51523, 51507, 51518, 51525 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-02-10 08:19:07 +0000 (Wed, 10 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-12-14 15:27:16 +0530 (Thu, 14 Dec 2017)" );
	script_name( "Oracle Mysql Security Updates (jan2012-366304) 02 - Windows" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  unspecified errors in MySQL Server." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to affect integrity, availability
  and confidentiality." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.5.x on Windows" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html" );
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
if(version_in_range( version: vers, test_version: "5.5", test_version2: "5.5.19" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

