if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902972" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 59791 );
	script_cve_id( "CVE-2013-1302" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-05-15 18:20:36 +0530 (Wed, 15 May 2013)" );
	script_name( "Microsoft Lync Attendee Remote Code Execution Vulnerability (2834695)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2827752" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2827751" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-041" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "secpod_ms_lync_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker could execute arbitrary
  code in the context of the current user by sharing specially crafted
  content, such as a file or a program, as a presentation in a Lync or
  Communicator session and then convince a user to view or share the
  specially crafted content." );
	script_tag( name: "affected", value: "Microsoft Lync Attendee 2010." );
	script_tag( name: "insight", value: "A use-after-free error within the Lync control can be exploited to
  dereference already freed memory." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-041." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(get_kb_item( "MS/Lync/Attendee/Ver" )){
	path = get_kb_item( "MS/Lync/Attendee/path" );
	if(path){
		oglVer = fetch_file_version( sysPath: path, file_name: "Appshapi.dll" );
		if(oglVer){
			if(version_in_range( version: oglVer, test_version: "4.0", test_version2: "4.0.7577.4377" )){
				report = report_fixed_ver( installed_version: oglVer, vulnerable_range: "4.0 - 4.0.7577.4377", install_path: path );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}

