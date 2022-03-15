if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813182" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-8173" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-09 14:32:27 +0530 (Wed, 09 May 2018)" );
	script_name( "Microsoft Infopath 2013 Service Pack 1 Elevation of Privilege Vulnerability (KB3162075)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3162075" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in Microsoft
  InfoPath when the software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Infopath 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3162075" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if( registry_key_exists( key: "SOFTWARE\\Microsoft\\Office\\15.0\\InfoPath\\InstallRoot" ) ){
	new_key = "SOFTWARE\\Microsoft\\Office\\15.0\\InfoPath\\InstallRoot";
}
else {
	if(registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Microsoft\\Office\\15.0\\InfoPath\\InstallRoot" )){
		new_key = "SOFTWARE\\Microsoft\\Office\\15.0\\InfoPath\\InstallRoot";
	}
}
if(!new_key){
	exit( 0 );
}
infoPath = registry_get_sz( key: new_key, item: "Path" );
if(infoPath){
	exeVer = fetch_file_version( sysPath: infoPath, file_name: "ipeditor.dll" );
	if(IsMatchRegexp( exeVer, "^(15\\.)" )){
		if(version_is_less( version: exeVer, test_version: "15.0.5027.1000" )){
			report = report_fixed_ver( file_checked: infoPath + "\\ipeditor.dll", file_version: exeVer, vulnerable_range: "15.0 - 15.0.5027.0999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

