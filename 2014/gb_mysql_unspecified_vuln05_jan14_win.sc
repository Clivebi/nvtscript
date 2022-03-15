if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804076" );
	script_version( "2021-02-10T08:19:07+0000" );
	script_cve_id( "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0402" );
	script_bugtraq_id( 64904, 64877, 64908 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-02-10 08:19:07 +0000 (Wed, 10 Feb 2021)" );
	script_tag( name: "creation_date", value: "2014-01-21 18:15:24 +0530 (Tue, 21 Jan 2014)" );
	script_name( "Oracle MySQL Multiple Unspecified vulnerabilities - 05 Jan14 (Windows)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is prone to multiple unspecified
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified errors in the MySQL Server component via unknown vectors related
  to Optimizer, InnoDB, and Locking." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to manipulate certain data
  and cause a DoS (Denial of Service)." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.1.71 and earlier, 5.5.33 and earlier, and 5.6.13
  and earlier on Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56491" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(IsMatchRegexp( vers, "^5\\.[156]" )){
	if(version_in_range( version: vers, test_version: "5.1", test_version2: "5.1.71" ) || version_in_range( version: vers, test_version: "5.5", test_version2: "5.5.33" ) || version_in_range( version: vers, test_version: "5.6", test_version2: "5.6.13" )){
		security_message( port: port );
		exit( 0 );
	}
}

