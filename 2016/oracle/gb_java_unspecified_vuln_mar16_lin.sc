CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108392" );
	script_version( "2021-08-20T15:19:58+0000" );
	script_cve_id( "CVE-2016-0636" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-20 15:19:58 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-28 14:58:10 +0530 (Mon, 28 Mar 2016)" );
	script_name( "Oracle Java SE JRE Unspecified Vulnerability March 2016 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity and availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Java SE 7 update 97, 8 update 73,
  8 update 74 and prior on Linux." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/alert-cve-2016-0636-2949497.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
jrePath = infos["location"];
if(IsMatchRegexp( jreVer, "^(1\\.(7|8))" )){
	if(version_in_range( version: jreVer, test_version: "1.7.0", test_version2: "1.7.0.97" ) || version_in_range( version: jreVer, test_version: "1.8.0", test_version2: "1.8.0.74" )){
		report = report_fixed_ver( installed_version: jreVer, fixed_version: "Apply the patch", install_path: jrePath );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

