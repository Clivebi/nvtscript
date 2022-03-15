if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806117" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2015-2510" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-09-09 14:26:26 +0530 (Wed, 09 Sep 2015)" );
	script_name( "Microsoft Lync Buffer Overflow Vulnerability (3089656)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-097." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to improper handling of
  TrueType fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "- Microsoft Lync 2010

  - Microsoft Lync 2013" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085500" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3081087" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-097" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "secpod_ms_lync_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Lync/Installed" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(get_kb_item( "MS/Lync/Ver" )){
	path = get_kb_item( "MS/Lync/path" );
	if(!path){
		path = get_kb_item( "MS/Lync/Basic/path" );
	}
	if(path){
		for ver in make_list( "",
			 "OFFICE14",
			 "OFFICE15" ) {
			commVer = fetch_file_version( sysPath: path + ver, file_name: "Rtmpltfm.dll" );
			if(commVer){
				if( IsMatchRegexp( commVer, "^4" ) ){
					Vulnerable_range = "4..0 - 4.0.7577.4477";
				}
				else {
					if(IsMatchRegexp( commVer, "^5" )){
						Vulnerable_range = "5 - 5.0.8687.138";
					}
				}
				if(version_in_range( version: commVer, test_version: "5.0", test_version2: "5.0.8687.138" ) || version_in_range( version: commVer, test_version: "4.0", test_version2: "4.0.7577.4477" )){
					report = "File checked:     " + path + ver + "\\Rtmpltfm.dll" + "\n" + "File version:     " + commVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
					security_message( data: report );
					exit( 0 );
				}
			}
		}
	}
}

