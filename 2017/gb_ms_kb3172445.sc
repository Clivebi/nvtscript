if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811201" );
	script_version( "2021-09-14T13:41:20+0000" );
	script_cve_id( "CVE-2017-8511", "CVE-2017-8512" );
	script_bugtraq_id( 98815, 98816 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 13:41:20 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-15 14:24:16 +0530 (Thu, 15 Jun 2017)" );
	script_name( "Microsoft SharePoint Server Multiple RCE Vulnerabilities (KB3172445)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3172445" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to Microsoft Office software failing
  to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to use a specially crafted file and
  perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft SharePoint Server 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3172445" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_mandatory_keys( "MS/SharePoint/Server/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:sharepoint_server", exit_no_version: TRUE )){
	exit( 0 );
}
shareVer = infos["version"];
if(!shareVer || !IsMatchRegexp( shareVer, "^15\\." )){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Office15.OSERVER", item: "InstallLocation" );
if(path){
	path = path + "\\15.0\\WebServices\\ConversionServices";
	dllVer = fetch_file_version( sysPath: path, file_name: "microsoft.office.server.native.dll" );
	if(dllVer && IsMatchRegexp( dllVer, "^15\\." )){
		if(version_is_less( version: dllVer, test_version: "15.0.4919.1000" )){
			report = "File checked:     " + path + "\\microsoft.office.server.native.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4919.0999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

