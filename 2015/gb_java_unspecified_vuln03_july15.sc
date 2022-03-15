CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805728" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-2596" );
	script_bugtraq_id( 75887 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-07-20 17:10:19 +0530 (Mon, 20 Jul 2015)" );
	script_name( "Oracle Java SE JRE Unspecified Vulnerability-03 July 2015 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  JRE and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to unspecified
  flaws related to unspecified vectors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to have an impact on integrity." );
	script_tag( name: "affected", value: "Oracle Java SE 7 update 80 on Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!jreVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( jreVer, "^(1\\.7)" )){
	if(version_in_range( version: jreVer, test_version: "1.7.0", test_version2: "1.7.0.80" )){
		report = report_fixed_ver( installed_version: jreVer, fixed_version: "Apply the patch from the referenced advisory." );
		security_message( data: report );
		exit( 0 );
	}
}

