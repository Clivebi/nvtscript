CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812737" );
	script_version( "2021-06-30T03:16:04+0000" );
	script_cve_id( "CVE-2018-2575", "CVE-2018-3110" );
	script_bugtraq_id( 102547 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-30 03:16:04 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-01-19 16:41:33 +0530 (Fri, 19 Jan 2018)" );
	script_name( "Oracle Database Server 'Core RDBMS' And 'Java VM' Components Unspecified Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Oracle Database Server
  and is prone to multiple unspecified security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple unspecified
  errors in the components 'Core RDBMS' and 'Java VM'." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity and availability via unknown
  vectors." );
	script_tag( name: "affected", value: "Oracle Database Server versions
  11.2.0.4, 12.2.0.1" );
	script_tag( name: "solution", value: "See the referenced vendor advisories for a solution." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/alert-cve-2018-3110-5032149.html" );
	script_xref( name: "URL", value: "https://blogs.oracle.com/oraclesecurity/security-alert-cve-2018-3110-released" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc", "os_detection.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!dbport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: dbport, exit_no_version: TRUE )){
	exit( 0 );
}
dbVer = infos["version"];
path = infos["location"];
if(dbVer == "11.2.0.4" || dbVer == "12.2.0.1"){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch", install_path: path );
	security_message( data: report, port: dbport );
	exit( 0 );
}
exit( 0 );

