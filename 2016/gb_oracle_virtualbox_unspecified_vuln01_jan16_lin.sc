CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806991" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2016-0495", "CVE-2015-3195" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-19 17:27:00 +0000 (Tue, 19 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-01-22 16:51:21 +0530 (Fri, 22 Jan 2016)" );
	script_name( "Oracle Virtualbox Unspecified Vulnerability - 01 Jan16 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to have an impact on availability." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 4.3.36
  and 5.0.14  on Linux." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  4.3.36, 5.0.14 or later on Linux." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if( version_in_range( version: virtualVer, test_version: "4.0.0", test_version2: "4.3.35" ) ){
	fix = "4.3.36";
	VULN = TRUE;
}
else {
	if(version_in_range( version: virtualVer, test_version: "5.0.0", test_version2: "5.0.13" )){
		fix = "5.0.14";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: virtualVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

