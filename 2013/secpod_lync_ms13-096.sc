if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903421" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3906" );
	script_bugtraq_id( 63530 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-11 13:17:21 +0530 (Wed, 11 Dec 2013)" );
	script_name( "Microsoft Lync Remote Code Execution Vulnerability (2908005)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
Microsoft Bulletin MS13-096." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "The flaw is due to an error when handling TIFF files within the Microsoft
Graphics Component (GDI+) and can be exploited to cause a memory corruption." );
	script_tag( name: "affected", value: "- Microsoft Lync 2010

  - Microsoft Lync 2013" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
code in the context of the currently logged-in user, which may lead to a
complete compromise of an affected computer." );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2899397" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2850057" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-096" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "secpod_ms_lync_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Lync/Ver", "MS/Lync/path" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(get_kb_item( "MS/Lync/Ver" )){
	path = get_kb_item( "MS/Lync/path" );
	if(path){
		commVer = fetch_file_version( sysPath: path, file_name: "Rtmpltfm.dll" );
		if(commVer){
			if(version_in_range( version: commVer, test_version: "5.0", test_version2: "5.0.8308.382" ) || version_in_range( version: commVer, test_version: "4.0", test_version2: "4.0.7577.4414" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

