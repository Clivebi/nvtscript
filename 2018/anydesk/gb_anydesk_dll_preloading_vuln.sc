CPE = "cpe:/a:anydesk:anydesk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813554" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_cve_id( "CVE-2018-13102" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-11 17:23:00 +0000 (Tue, 11 Sep 2018)" );
	script_tag( name: "creation_date", value: "2018-07-06 16:47:10 +0530 (Fri, 06 Jul 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "AnyDesk DLL Preloading Privilege Escalation Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with AnyDesk and is
  prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to improper sanitization
  of an unknown function in the component DLL Loader." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to escalate privilege and gain control of the application." );
	script_tag( name: "affected", value: "AnyDesk version before 4.1.3 on Windows 7
  SP1" );
	script_tag( name: "solution", value: "Update AnyDesk to version 4.1.3 or above. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://download.anydesk.com/changelog.txt" );
	script_xref( name: "URL", value: "https://anydesk.com/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_anydesk_detect_win.sc" );
	script_mandatory_keys( "AnyDesk/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win7: 1 ) <= 0){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
adVer = infos["version"];
adPath = infos["location"];
if(version_is_less( version: adVer, test_version: "4.1.3" )){
	report = report_fixed_ver( installed_version: adVer, fixed_version: "4.1.3", install_path: adPath );
	security_message( data: report );
	exit( 0 );
}

