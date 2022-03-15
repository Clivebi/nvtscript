if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108425" );
	script_version( "2020-12-30T00:35:59+0000" );
	script_cve_id( "CVE-2014-4247" );
	script_bugtraq_id( 68626 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-30 00:35:59 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "creation_date", value: "2014-07-25 10:43:38 +0530 (Fri, 25 Jul 2014)" );
	script_name( "Oracle Java SE JRE Unspecified Vulnerability-04 Jul 2014 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE JRE and is prone to some unspecified
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error related to the JavaFX subcomponent" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Oracle Java SE 8 update 5.0 and prior on Linux." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59501" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1030577" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:oracle:jre",
	 "cpe:/a:sun:jre" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^1\\.8" )){
	if(version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.5" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "1.8.0 - 1.8.0.5", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

