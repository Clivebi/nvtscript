CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806604" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-4896", "CVE-2015-4813" );
	script_bugtraq_id( 77198, 77185 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-11-02 13:04:44 +0530 (Mon, 02 Nov 2015)" );
	script_name( "Oracle Virtualbox Multiple Unspecified Vulnerabilities-01 Nov15 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  virtualBox and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to some
  unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to have an impact on availability." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 4.0.34,
  4.1.42, 4.2.34, 4.3.32, and 5.0.8 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  4.0.34, 4.1.42, 4.2.34, 4.3.32, 5.0.8  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_sun_virtualbox_detect_lin.sc" );
	script_mandatory_keys( "Sun/VirtualBox/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^(4|5)\\." )){
	if(version_in_range( version: virtualVer, test_version: "4.0.0", test_version2: "4.0.33" )){
		fix = "4.0.34";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.1.0", test_version2: "4.1.41" )){
		fix = "4.1.42";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.2.0", test_version2: "4.2.33" )){
		fix = "4.2.34";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.3.0", test_version2: "4.3.31" )){
		fix = "4.3.32";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "5.0.0", test_version2: "5.0.7" )){
		fix = "5.0.8";
		VULN = TRUE;
	}
	if(VULN){
		report = "Installed version: " + virtualVer + "\n" + "Fixed version:     " + fix + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

