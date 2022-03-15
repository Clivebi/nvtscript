CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814799" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2019-2656", "CVE-2019-2657", "CVE-2019-2574", "CVE-2019-2721", "CVE-2019-2722", "CVE-2019-2723", "CVE-2019-2690", "CVE-2019-2679", "CVE-2019-2678", "CVE-2019-2703", "CVE-2019-2696", "CVE-2019-2680" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-18 13:17:52 +0530 (Thu, 18 Apr 2019)" );
	script_name( "Oracle VirtualBox Security Updates (apr2019-5072813) 02 - Linux" );
	script_tag( name: "summary", value: "The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  unspecified vulnerabilities in the core of Oracle VirtualBox" );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow a local attacker to have an impact on
  confidentiality, integrity and availability" );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.2.28 and
  6.x prior to 6.0.6 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox 5.2.28 or
  6.0.6 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixOVIR" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_sun_virtualbox_detect_lin.sc" );
	script_mandatory_keys( "Sun/VirtualBox/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if( IsMatchRegexp( version, "^6\\." ) && version_is_less( version: version, test_version: "6.0.6" ) ){
	fix = "6.0.6";
}
else {
	if(version_is_less( version: version, test_version: "5.2.28" )){
		fix = "5.2.28";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

