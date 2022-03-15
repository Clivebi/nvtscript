if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807926" );
	script_version( "2021-02-12T11:09:59+0000" );
	script_cve_id( "CVE-2016-0663", "CVE-2016-0658", "CVE-2016-0656", "CVE-2016-0653", "CVE-2016-0654", "CVE-2016-0652" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-04-25 16:10:46 +0530 (Mon, 25 Apr 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Oracle MySQL Server 5.7 <= 5.7.10 Security Update (cpuapr2016v3) - Windows" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified errors exist in the 'MySQL Server' component via
  unknown vectors." );
	script_tag( name: "impact", value: "Successful exploitation will allow local users to affect availability
  via unknown vectors." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.7 through 5.7.10." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuapr2016v3.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuapr2016v3" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
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
if(version_in_range( version: vers, test_version: "5.7", test_version2: "5.7.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See the referenced vendor advisory", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

