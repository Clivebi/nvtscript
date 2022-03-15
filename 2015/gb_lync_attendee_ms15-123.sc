if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806156" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-6061" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-11-11 10:21:46 +0530 (Wed, 11 Nov 2015)" );
	script_name( "Microsoft Lync Attendee Information Disclosure Vulnerability (3105872)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-123." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to improper handling
  of JavaScript content." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker disclosure if an attacker invites a target user to an instant
  message session and then sends that user a message containing specially crafted
  JavaScript content." );
	script_tag( name: "affected", value: "Microsoft Lync Attendee 2010." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3096738" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3096736" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3096735" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-123" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_lync_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_smb_func.inc.sc");
require("version_func.inc.sc");
path = get_kb_item( "MS/Lync/Attendee/path" );
if(path){
	dllVer = fetch_file_version( sysPath: path, file_name: "Rtmpltfm.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "4.0", test_version2: "4.0.7577.4483" )){
			report = "File checked:     " + path + "Rtmpltfm.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range:  4.0 - 4.0.7577.4483" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}

