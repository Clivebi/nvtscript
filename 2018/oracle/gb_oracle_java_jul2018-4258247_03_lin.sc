CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813685" );
	script_version( "2021-08-20T14:11:31+0000" );
	script_cve_id( "CVE-2018-2972" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 14:11:31 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-07-18 11:26:47 +0530 (Wed, 18 Jul 2018)" );
	script_name( "Oracle Java SE Security Updates-03 (jul2018-4258247) Linux" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Check if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error
  in the Java SE Security component." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to access sensitive data." );
	script_tag( name: "affected", value: "Oracle Java SE version 10.0 through 10.0.1 on
  Linux" );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html" );
	script_xref( name: "URL", value: "https://securitytracker.com/id/1041302" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/java/javase/downloads/index.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
jreVer = infos["version"];
path = infos["location"];
if(jreVer == "10.0.1" || jreVer == "10"){
	report = report_fixed_ver( installed_version: jreVer, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

