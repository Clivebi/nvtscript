if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805560" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-1671" );
	script_bugtraq_id( 74490 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-05-14 12:44:26 +0530 (Thu, 14 May 2015)" );
	script_name( "Microsoft Lync Attendee Remote Code Execution Vulnerability (3057110)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-044." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper handling of
  TrueType fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Microsoft Lync Attendee 2010." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3057110" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-044" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_lync_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
path = get_kb_item( "MS/Lync/Attendee/path" );
if(path){
	oglVer = fetch_file_version( sysPath: path, file_name: "Ogl.dll" );
	if(oglVer){
		if(version_in_range( version: oglVer, test_version: "4.0", test_version2: "4.0.7577.4460" )){
			report = report_fixed_ver( installed_version: oglVer, vulnerable_range: "4.0 - 4.0.7577.4460", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}

