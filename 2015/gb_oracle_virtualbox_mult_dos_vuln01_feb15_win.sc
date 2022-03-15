CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805428" );
	script_version( "2019-07-05T09:12:25+0000" );
	script_cve_id( "CVE-2015-0418", "CVE-2015-0377" );
	script_bugtraq_id( 72194, 72219 );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 09:12:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-02-02 10:04:10 +0530 (Mon, 02 Feb 2015)" );
	script_name( "Oracle Virtualbox Multiple DoS Vulnerabilities Feb15 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle VM
  virtualBox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow a local
  attacker to conduct a denial of service attack." );
	script_tag( name: "affected", value: "VirtualBox versions 3.2.x before
  3.2.26, 4.0.x before 4.0.28, 4.1.x before 4.1.36, 4.2.x before 4.2.28 on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  3.2.26 or 4.0.28 or 4.1.36 or 4.2.28 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_sun_virtualbox_detect_win.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^((3|4)\\.(0|1|2))" )){
	if(version_in_range( version: virtualVer, test_version: "3.2.0", test_version2: "3.2.25" )){
		fix = "3.2.26";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.0.0", test_version2: "4.0.27" )){
		fix = "4.0.28";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.1.0", test_version2: "4.1.35" )){
		fix = "4.1.36";
		VULN = TRUE;
	}
	if(version_in_range( version: virtualVer, test_version: "4.2.0", test_version2: "4.2.27" )){
		fix = "4.2.28";
		VULN = TRUE;
	}
	if(VULN){
		report = "Installed version: " + virtualVer + "\n" + "Fixed version:     " + fix + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

