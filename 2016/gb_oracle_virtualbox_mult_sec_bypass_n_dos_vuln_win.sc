CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809075" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-5501", "CVE-2016-6304", "CVE-2016-5610", "CVE-2016-5538", "CVE-2016-5613", "CVE-2016-5611", "CVE-2016-5608" );
	script_bugtraq_id( 93687, 93150, 93711, 93697, 93728, 93744, 93718 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-20 01:29:00 +0000 (Fri, 20 Apr 2018)" );
	script_tag( name: "creation_date", value: "2016-10-21 14:40:28 +0530 (Fri, 21 Oct 2016)" );
	script_name( "Oracle Virtualbox Multiple Security Bypass And DoS Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to multiple security bypass and denial of service
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  unspecified errors in core and openssl component." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain elevated privileges, to partially access and modify data
  and cause partial denial of service conditions." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.0.28 and
  prior to 5.1.8 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  5.0.28 or 5.1.8 or later on Windows." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if( IsMatchRegexp( virtualVer, "^5\\.0\\." ) ){
	if(version_is_less( version: virtualVer, test_version: "5.0.28" )){
		fix = "5.0.28";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( virtualVer, "^5\\.1\\." )){
		if(version_is_less( version: virtualVer, test_version: "5.1.8" )){
			fix = "5.1.8";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: virtualVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

