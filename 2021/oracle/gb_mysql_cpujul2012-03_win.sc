CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117267" );
	script_version( "2021-03-18T11:53:07+0000" );
	script_tag( name: "last_modification", value: "2021-03-18 11:53:07 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-18 11:21:54 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_cve_id( "CVE-2012-1735", "CVE-2012-1757", "CVE-2012-1756" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server 5.5.x <= 5.5.23 Security Update (cpujul2012) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple unspecified
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "impact", value: "The flaws allow remote authenticated users to affect
  availability via unknown vectors related to the 'Server Optimizer' and 'InnoDB'
  package / privilege." );
	script_tag( name: "affected", value: "Oracle MySQL Server 5.5.x through 5.5.23." );
	script_tag( name: "solution", value: "Update to version 5.5.24 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujul2012.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpujul2012" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "5.5", test_version2: "5.5.23" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.24", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

