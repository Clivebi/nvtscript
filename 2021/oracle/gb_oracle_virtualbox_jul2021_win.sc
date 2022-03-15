CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818165" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2021-2409", "CVE-2021-2454", "CVE-2021-2443", "CVE-2021-2442" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-23 13:30:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-28 15:39:44 +0530 (Wed, 28 Jul 2021)" );
	script_name( "Oracle VirtualBox Security Updates(jul2021) 01 - Windows" );
	script_tag( name: "summary", value: "This host is missing a security update
  according to Oracle." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors
  in 'Core' component." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 6.1.24 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version 6.1.24 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujul2021.html" );
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
virtualVer = infos["version"];
path = infos["location"];
if(version_is_less( version: virtualVer, test_version: "6.1.24" )){
	report = report_fixed_ver( installed_version: virtualVer, fixed_version: "6.1.24", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

