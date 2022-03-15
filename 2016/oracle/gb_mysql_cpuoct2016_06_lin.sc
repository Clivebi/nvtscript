if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809381" );
	script_version( "2021-02-12T11:09:59+0000" );
	script_cve_id( "CVE-2016-5609", "CVE-2016-5627", "CVE-2016-5630", "CVE-2016-8284" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-10-19 15:51:27 +0530 (Wed, 19 Oct 2016)" );
	script_name( "Oracle MySQL Server 5.6 <= 5.6.31 / 5.7 <= 5.7.13 Security Update (cpuoct2016) - Linux" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple unspecified errors within
  the 'Server: DML', 'Server: Replication' and 'Server: InnoDB' components." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability will allow a remote
  authenticated user to cause denial of service conditions." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.6 through 5.6.31 and 5.7 through 5.7.13." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuoct2016.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuoct2016" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
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
if(version_in_range( version: vers, test_version: "5.6", test_version2: "5.6.31" ) || version_in_range( version: vers, test_version: "5.7", test_version2: "5.7.13" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See the referenced vendor advisory", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

