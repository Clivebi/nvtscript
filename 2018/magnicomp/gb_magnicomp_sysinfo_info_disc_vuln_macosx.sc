CPE = "cpe:/a:magnicomp:sysinfo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814052" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-7268" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:01:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-09-27 12:51:21 +0530 (Thu, 27 Sep 2018)" );
	script_name( "MagniComp SysInfo Information Disclosure Vulnerability (MAC OS X)" );
	script_tag( name: "summary", value: "This host is installed with MagniComp SysInfo
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an access bypass error
  related to a combination of setuid binary and verbose debugging." );
	script_tag( name: "affected", value: "MagniComp SysInfo before version 10-H81." );
	script_tag( name: "solution", value: "Upgrade to MagniComp SysInfo 10-H81 or
  later. Please see the references for more information." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://dl.packetstormsecurity.net/1805-advisories/magnicomp-sysinfo-information-exposure.txt" );
	script_xref( name: "URL", value: "https://www.magnicomp.com" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_magnicomp_sysinfo_detect_macosx.sc" );
	script_mandatory_keys( "MagniComp/SysInfo/Macosx/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
mgVer = infos["version"];
mgPath = infos["location"];
if(version_is_less( version: mgVer, test_version: "10.0 H81" )){
	report = report_fixed_ver( installed_version: mgVer, fixed_version: "10-H81", install_path: mgPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

