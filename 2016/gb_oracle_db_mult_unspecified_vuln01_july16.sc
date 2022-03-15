CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808702" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2016-3448", "CVE-2016-3467" );
	script_bugtraq_id( 91885, 91894 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)" );
	script_tag( name: "creation_date", value: "2016-07-21 18:38:34 +0530 (Thu, 21 Jul 2016)" );
	script_name( "Oracle Database Server Multiple Unspecified Vulnerabilities -01 July16" );
	script_tag( name: "summary", value: "This host is running  Oracle Database Server
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple
  unspecified vulnerabilities in the Application Express component." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database Server version before 5.0.4" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html" );
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
if(version_is_less( version: dbVer, test_version: "5.0.4" )){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch" );
	security_message( data: report, port: dbPort );
	exit( 0 );
}

