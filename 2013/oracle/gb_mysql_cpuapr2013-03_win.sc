CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117208" );
	script_version( "2021-02-12T11:09:59+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-09 09:51:55 +0000 (Tue, 09 Feb 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_cve_id( "CVE-2013-2395", "CVE-2013-2381", "CVE-2013-1570", "CVE-2013-1567", "CVE-2013-1566" );
	script_bugtraq_id( 59173, 59215, 59216, 59232, 59205 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server 5.6 <= 5.6.10 Security Update (cpuapr2013) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified error in Data Manipulation Language, Server Privileges,
  MemCached and InnoDB." );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to affect
  confidentiality, integrity, and availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.6 through 5.6.10." );
	script_tag( name: "solution", value: "Update to version 5.6.11 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuapr2013.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuapr2013" );
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
if(version_in_range( version: version, test_version: "5.6", test_version2: "5.6.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.11", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

