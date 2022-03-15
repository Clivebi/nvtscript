CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811012" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_cve_id( "CVE-2017-3538" );
	script_bugtraq_id( 97698 );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-25 15:31:17 +0530 (Tue, 25 Apr 2017)" );
	script_name( "Oracle Virtualbox Security Bypass Vulnerability - 01 Apr17 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified error
  in the 'Shared Folder' component of the application." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.0.34
  and prior to 5.1.16 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox 5.0.34, 5.1.16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_oracle_virtualbox_detect_macosx.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( IsMatchRegexp( virtualVer, "^(5\\.0)" ) ){
	if(version_is_less( version: virtualVer, test_version: "5.0.34" )){
		fix = "5.0.34";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( virtualVer, "^(5\\.1)" )){
		if(version_is_less( version: virtualVer, test_version: "5.1.16" )){
			fix = "5.1.16";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: virtualVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

