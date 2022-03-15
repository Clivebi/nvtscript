CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813006" );
	script_version( "2019-05-17T10:45:27+0000" );
	script_cve_id( "CVE-2011-2242" );
	script_tag( name: "cvss_base", value: "1.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:M/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "creation_date", value: "2018-03-07 15:14:30 +0530 (Wed, 07 Mar 2018)" );
	script_name( "Oracle Database Server Core RDBMS Component Unspecified Vulnerability -01 Mar18" );
	script_tag( name: "summary", value: "This host is running  Oracle Database Server
  and is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error in
  component 'Core RDBMS'." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to affect confidentiality via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database Server version 11.2.0.1 and
  11.2.0.2." );
	script_tag( name: "solution", value: "Apply the patche from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/topics/security/cpujuly2011-313328.html" );
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
if(dbVer == "11.2.0.1" || dbVer == "11.2.0.2"){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the patch", install_path: path );
	security_message( port: dbport, data: report );
	exit( 0 );
}
exit( 0 );

