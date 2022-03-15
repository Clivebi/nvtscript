CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806605" );
	script_version( "2019-07-05T09:12:25+0000" );
	script_cve_id( "CVE-2015-4856" );
	script_bugtraq_id( 77202 );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 09:12:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-11-02 13:23:55 +0530 (Mon, 02 Nov 2015)" );
	script_name( "Oracle Virtualbox Unspecified Vulnerability Nov15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to have an impact on availability." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 4.0.30,
  4.1.38, 4.2.30, 4.3.26, and 5.0.0 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  4.0.30, 4.1.38, 4.2.30, 4.3.26, 5.0.0 or later on Windows." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_sun_virtualbox_detect_win.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^4\\." )){
	if(version_in_range( version: virtualVer, test_version: "4.0.0", test_version2: "4.0.29" )){
		fix = "4.0.30";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.1.0", test_version2: "4.1.37" )){
		fix = "4.1.38";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.2.0", test_version2: "4.2.29" )){
		fix = "4.2.30";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.3.0", test_version2: "4.3.25" )){
		fix = "4.3.26";
		VULN = TRUE;
	}
	if(VULN){
		report = "Installed version: " + virtualVer + "\n" + "Fixed version:     " + fix + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

