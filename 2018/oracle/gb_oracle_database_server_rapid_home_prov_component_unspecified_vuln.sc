CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814143" );
	script_version( "2021-06-30T02:00:35+0000" );
	script_cve_id( "CVE-2018-7489" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-30 02:00:35 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-25 01:15:00 +0000 (Thu, 25 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-10-17 12:29:56 +0530 (Wed, 17 Oct 2018)" );
	script_name( "Oracle Database Server 'Rapid Home Provisioning' Component Unspecified Vulnerability" );
	script_tag( name: "summary", value: "This host is running Oracle Database Server
  and is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error in
  component 'Rapid Home Provisioning'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to have an impact on availability and integrity via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database Server version 18c" );
	script_tag( name: "solution", value: "Apply appropriate patch provided by the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html#AppendixDB" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/database/in-memory/downloads/index.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
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
if(dbVer == "18.1.0"){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the patch", install_path: path );
	security_message( port: dbport, data: report );
	exit( 0 );
}
exit( 0 );

