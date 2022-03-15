CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817706" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-2074", "CVE-2021-2129", "CVE-2021-2128", "CVE-2021-2086", "CVE-2021-2111", "CVE-2021-2112", "CVE-2021-2121", "CVE-2021-2124", "CVE-2021-2119", "CVE-2021-2120", "CVE-2021-2126", "CVE-2021-2131", "CVE-2021-2125", "CVE-2021-2073", "CVE-2021-2127", "CVE-2021-2130", "CVE-2021-2123" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-27 22:33:00 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-22 12:10:46 +0530 (Fri, 22 Jan 2021)" );
	script_name( "Oracle VirtualBox Security Updates(Jan2021) - Windows" );
	script_tag( name: "summary", value: "Oracle VM VirtualBox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors
  in 'Core' component." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability." );
	script_tag( name: "affected", value: "VirtualBox versions 6.1.x prior to 6.1.18
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version 6.1.18
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujan2021.html#AppendixOVIR" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
version = infos["version"];
path = infos["location"];
if(IsMatchRegexp( version, "^6\\.1\\." ) && version_is_less( version: version, test_version: "6.1.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.1.18", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

