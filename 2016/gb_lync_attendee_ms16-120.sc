if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809445" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-3209", "CVE-2016-3262", "CVE-2016-3263", "CVE-2016-3396", "CVE-2016-7182" );
	script_bugtraq_id( 93385, 93390, 93394, 93380, 93395 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-10-12 12:47:25 +0530 (Wed, 12 Oct 2016)" );
	script_name( "Microsoft Lync Attendee Multiple Vulnerabilities (3192884)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-120." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The Windows Graphics Device Interface (GDI) improperly handles objects
    in memory.

  - The windows font library which improperly handles specially crafted
    embedded fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system and gain
  access to potentially sensitive information." );
	script_tag( name: "affected", value: "Microsoft Lync Attendee 2010." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3192884" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-120" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
lyncPath = get_kb_item( "MS/Lync/Attendee/path" );
if(lyncPath){
	dllVer = fetch_file_version( sysPath: lyncPath, file_name: "Rtmpltfm.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "4.0", test_version2: "4.0.7577.4520" )){
			report = "File checked:     " + lyncPath + "Rtmpltfm.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: 4.0 - 4.0.7577.4520" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}

