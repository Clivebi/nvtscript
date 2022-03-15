CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807047" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2015-4755", "CVE-2016-3488", "CVE-2016-5572", "CVE-2016-5497", "CVE-2016-5516", "CVE-2017-3240", "CVE-2017-3567", "CVE-2017-10120" );
	script_bugtraq_id( 75882, 91905, 93634, 93631, 93626, 95477, 97873, 99867 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)" );
	script_name( "Oracle Database Server Unspecified Vulnerability - 07 Jan16" );
	script_tag( name: "summary", value: "This host is running  Oracle Database Server
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple unspecified errors.

  - An unspecified error related to component 'RDBMS Security'." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity, and availability
  via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database Server version
  12.1.0.2" );
	script_tag( name: "solution", value: "Apply the patches from the referenced advisories." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixDB" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!dbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dbVer = get_app_version( cpe: CPE, port: dbPort )){
	exit( 0 );
}
if(version_is_equal( version: dbVer, test_version: "12.1.0.2" )){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch" );
	security_message( data: report, port: dbPort );
	exit( 0 );
}
exit( 99 );

