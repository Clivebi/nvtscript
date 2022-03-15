CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814653" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2018-3309" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-01-16 15:28:08 +0530 (Wed, 16 Jan 2019)" );
	script_name( "Oracle VirtualBox Security Updates (jan2019-5072801) 02 - Linux" );
	script_tag( name: "summary", value: "The host is installed with Oracle VM
  VirtualBox and is prone to an unspecified security vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified
  error in Core component." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to affect confidentiality, availability and integrity via
  unknown vectors." );
	script_tag( name: "affected", value: "VirtualBox versions Prior to 5.2.22
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox Prior to 5.2.22 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html" );
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
virtualVer = infos["version"];
path = infos["location"];
if(version_is_less( version: virtualVer, test_version: "5.2.22" )){
	report = report_fixed_ver( installed_version: virtualVer, fixed_version: "5.2.22", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

