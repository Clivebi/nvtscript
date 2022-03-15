if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811755" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_cve_id( "CVE-2017-8676", "CVE-2017-8696", "CVE-2017-8695" );
	script_bugtraq_id( 100755, 100780, 100773 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-21 18:47:00 +0000 (Thu, 21 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-09-13 11:33:44 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft Lync 2010 Multiple Vulnerabilities (KB4025865)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4025865" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the way that the Windows Graphics Device Interface (GDI) handles
    objects in memory.

  - An error when Windows Uniscribe improperly discloses the contents of its memory.

  - An error due to the way Windows Uniscribe handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to retrieve information from a targeted system to further compromise the user's
  system and take control of the affected system." );
	script_tag( name: "affected", value: "Microsoft Lync 2010 (32-bit and 64-bit)." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4025865" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "secpod_ms_lync_detect_win.sc" );
	script_mandatory_keys( "MS/Lync/Installed" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(get_kb_item( "MS/Lync/Ver" )){
	lyncPath = get_kb_item( "MS/Lync/path" );
	if(!lyncPath){
		lyncPath = get_kb_item( "MS/Lync/Basic/path" );
	}
	if(lyncPath){
		lyncPath1 = lyncPath + "OFFICE14";
		commVer = fetch_file_version( sysPath: lyncPath1, file_name: "Rtmpltfm.dll" );
		if(commVer){
			if(IsMatchRegexp( commVer, "^4" ) && version_in_range( version: commVer, test_version: "4.0", test_version2: "4.0.7577.4539" )){
				report = "File checked:     " + lyncPath1 + "\\Rtmpltfm.dll" + "\n" + "File version:     " + commVer + "\n" + "Vulnerable range: " + "4.0 - 4.0.7577.4539" + "\n";
				security_message( data: report );
			}
		}
	}
}
exit( 0 );

