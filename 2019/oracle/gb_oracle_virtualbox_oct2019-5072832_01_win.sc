CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815646" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2019-3002", "CVE-2019-3031", "CVE-2019-1547", "CVE-2019-3021", "CVE-2019-2984", "CVE-2019-2944", "CVE-2019-3026", "CVE-2019-3028", "CVE-2019-2926", "CVE-2019-3017", "CVE-2019-3005" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 19:41:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-10-16 12:29:49 +0530 (Wed, 16 Oct 2019)" );
	script_name( "Oracle VirtualBox Security Updates (oct2019-5072832) 01 - Windows" );
	script_tag( name: "summary", value: "The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors
  in 'Core' component." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.2.34 and
  6.x prior to 6.0.10 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version 5.2.34
  or 6.0.14 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_sun_virtualbox_detect_win.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( vers, "^6\\." ) && version_is_less( version: vers, test_version: "6.0.14" ) ){
	fix = "6.0.14";
}
else {
	if(version_is_less( version: vers, test_version: "5.2.34" )){
		fix = "5.2.34";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

