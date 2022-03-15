CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811532" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_cve_id( "CVE-2017-10202", "CVE-2017-10321", "CVE-2017-10190", "CVE-2017-10292" );
	script_bugtraq_id( 99865, 101329, 101335, 101350 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-19 12:14:58 +0530 (Wed, 19 Jul 2017)" );
	script_name( "Oracle Database Server 'OJVM' Component Unspecified Vulnerability" );
	script_tag( name: "summary", value: "This host is running  Oracle Database Server
  and is prone to multiple unspecified security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple
  unspecified errors in components 'Core RDBMS', 'Spatial (Apache Groovy)',
  'Java VM', 'WLM (Apache Tomcat)', 'XML Database', 'RDBMS Security' and
  'OJVM' components." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity, and availability
  via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database Server versions
  11.2.0.4, 12.1.0.2, 12.2.0.1" );
	script_tag( name: "solution", value: "Apply Vendor patches." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html" );
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
if(dbVer == "11.2.0.4" || dbVer == "12.1.0.2" || dbVer == "12.2.0.1"){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch" );
	security_message( data: report, port: dbPort );
	exit( 0 );
}

