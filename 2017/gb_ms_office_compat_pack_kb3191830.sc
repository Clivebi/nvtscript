if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810691" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_cve_id( "CVE-2017-0194" );
	script_bugtraq_id( 97436 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-04-12 11:03:42 +0530 (Wed, 12 Apr 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Compatibility Pack Information Disclosure Vulnerability (KB3191830)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office Compatibility Pack according to Microsoft KB3191830." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as Microsoft Office improperly
  discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information and use the
  information to compromise the user's computer or data." );
	script_tag( name: "affected", value: "Microsoft Office Compatibility Pack Service Pack 3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3191830" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/Office/ComptPack/Version", "SMB/Office/XLCnv/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!path){
	exit( 0 );
}
cmpPckVer = get_kb_item( "SMB/Office/ComptPack/Version" );
if(cmpPckVer && IsMatchRegexp( cmpPckVer, "^12\\." )){
	xlcnvVer = get_kb_item( "SMB/Office/XLCnv/Version" );
	if(xlcnvVer && IsMatchRegexp( xlcnvVer, "^12\\." )){
		offpath = path + "\\Microsoft Office\\Office12";
		sysVer = fetch_file_version( sysPath: offpath, file_name: "excelcnv.exe" );
		if(sysVer && IsMatchRegexp( sysVer, "^12\\." )){
			if(version_in_range( version: sysVer, test_version: "12.0", test_version2: "12.0.6766.4999" )){
				report = "File checked:      " + offpath + "\\excelcnv.exe" + "\n" + "File version:      " + sysVer + "\n" + "Vulnerable range:  12.0 - 12.0.6766.4999" + "\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}

