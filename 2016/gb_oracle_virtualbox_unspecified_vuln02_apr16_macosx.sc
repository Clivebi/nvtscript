CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807812" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2015-3197" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-21 02:29:00 +0000 (Tue, 21 Nov 2017)" );
	script_tag( name: "creation_date", value: "2016-04-25 18:12:24 +0530 (Mon, 25 Apr 2016)" );
	script_name( "Oracle Virtualbox Unspecified Vulnerability-02 Apr16 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to have an impact on confidentiality." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.0.16
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  5.0.16 or later on Mac OS X." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_in_range( version: virtualVer, test_version: "5.0.0", test_version2: "5.0.15" )){
	report = report_fixed_ver( installed_version: virtualVer, fixed_version: "5.0.16" );
	security_message( data: report );
	exit( 0 );
}

