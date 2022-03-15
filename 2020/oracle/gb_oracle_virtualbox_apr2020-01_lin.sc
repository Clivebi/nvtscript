CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816852" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-2902", "CVE-2020-2959", "CVE-2020-2905", "CVE-2020-2908", "CVE-2020-2758", "CVE-2020-2894", "CVE-2020-2929", "CVE-2020-2911", "CVE-2020-2907", "CVE-2020-2958", "CVE-2020-2951", "CVE-2020-2741", "CVE-2020-2748", "CVE-2020-2909" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 14:01:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-04-15 08:39:55 +0530 (Wed, 15 Apr 2020)" );
	script_name( "Oracle VirtualBox Security Update (cpuapr2020 - 01) - Linux" );
	script_tag( name: "summary", value: "Oracle VM VirtualBox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors
  in 'Core' component." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.2.40, 6.1.x
  prior to 6.1.6 and 6.0.x prior to 6.0.20." );
	script_tag( name: "solution", value: "Update to Oracle VirtualBox version 5.2.40
  or 6.0.20 or 6.1.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixOVIR" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if( IsMatchRegexp( version, "^6\\.0\\." ) && version_is_less( version: version, test_version: "6.0.20" ) ){
	fix = "6.0.20";
}
else {
	if( IsMatchRegexp( version, "^6\\.1\\." ) && version_is_less( version: version, test_version: "6.1.6" ) ){
		fix = "6.1.6";
	}
	else {
		if(version_is_less( version: version, test_version: "5.2.40" )){
			fix = "5.2.40";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

