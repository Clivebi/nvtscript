CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805537" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0470", "CVE-2015-0486" );
	script_bugtraq_id( 74149, 74145 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-04-21 17:16:10 +0530 (Tue, 21 Apr 2015)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Apr 2015 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  JRE and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the Hotspot subcomponent related to private method resolution.

  - An unspecified error related to the Deployment subcomponent." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain knowledge of potentially sensitive information and bypass certain
  sandbox restrictions." );
	script_tag( name: "affected", value: "Oracle Java SE 8 update 40 and prior
  on Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html" );
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
	if(version_in_range( version: jreVer, test_version: "1.8.0", test_version2: "1.8.0.40" )){
		report = report_fixed_ver( installed_version: jreVer, fixed_version: "Apply the patch from the referenced advisory." );
		security_message( data: report );
		exit( 0 );
	}
}

