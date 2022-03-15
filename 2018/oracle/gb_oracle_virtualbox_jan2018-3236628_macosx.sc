CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812643" );
	script_version( "2021-06-30T02:00:35+0000" );
	script_cve_id( "CVE-2018-2688", "CVE-2018-2689", "CVE-2018-2676", "CVE-2018-2698", "CVE-2018-2694", "CVE-2018-2693", "CVE-2018-2685", "CVE-2018-2686", "CVE-2018-2687", "CVE-2018-2690", "CVE-2017-5715", "CVE-2017-3735" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-30 02:00:35 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 19:30:00 +0000 (Tue, 23 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-01-17 13:17:22 +0530 (Wed, 17 Jan 2018)" );
	script_name( "Oracle VirtualBox Security Updates (jan2018-3236628) - MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - Multiple errors in the 'Core' component of the application.

  - An error in the 'Guest Additions' component of the application." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow local attackers to gain elevated privileges on
  the host system." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.1.32 and
  5.2.x prior to 5.2.6 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox 5.1.32 or 5.2.6
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_oracle_virtualbox_detect_macosx.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
virtualVer = infos["version"];
path = infos["location"];
if( IsMatchRegexp( virtualVer, "^5\\.2" ) && ( version_is_less( version: virtualVer, test_version: "5.2.6" ) ) ){
	fix = "5.2.6";
}
else {
	if(version_is_less( version: virtualVer, test_version: "5.1.32" )){
		fix = "5.1.32";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: virtualVer, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

