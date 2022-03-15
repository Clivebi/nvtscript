CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806511" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-4916", "CVE-2015-4908", "CVE-2015-4906", "CVE-2015-4901", "CVE-2015-4868" );
	script_bugtraq_id( 77221, 77223, 77214, 77226, 77225 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-10-27 11:40:31 +0530 (Tue, 27 Oct 2015)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Oct 2015 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  JRE and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple
  unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability via unknown
  vectors." );
	script_tag( name: "affected", value: "Oracle Java SE 8 update 60 and prior
  on Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/alerts-086861.html" );
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
if(IsMatchRegexp( jreVer, "^(1\\.8)" )){
	if(version_in_range( version: jreVer, test_version: "1.8.0", test_version2: "1.8.0.60" )){
		report = "Installed version: " + jreVer + "\n" + "Fixed version:     " + "Apply the patch" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

