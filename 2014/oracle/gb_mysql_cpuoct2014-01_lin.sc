CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808118" );
	script_version( "2021-02-12T11:09:59+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 13:42:43 +0530 (Fri, 03 Jun 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2014-0224", "CVE-2014-6489", "CVE-2014-6564", "CVE-2014-6474", "CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-3470" );
	script_bugtraq_id( 70511, 70525, 70448 );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server 5.6 <= 5.6.19 Security Update (cpuoct2014) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified errors in the MySQL Server component via unknown vectors
  related to SERVER:INNODB FULLTEXT SEARCH DML, SERVER:SP, and SERVER:MEMCACHED." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to disclose potentially
  sensitive information, gain escalated privileges, manipulate certain data, cause a DoS (Denial of Service),
  and compromise a vulnerable system." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.6 through 5.6.19." );
	script_tag( name: "solution", value: "Update to version 5.6.20 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuoct2014.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuoct2014" );
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
if(version_in_range( version: version, test_version: "5.6", test_version2: "5.6.19" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.20", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

