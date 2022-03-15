if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809750" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2016-7268", "CVE-2016-7276", "CVE-2016-7298", "CVE-2016-7275", "CVE-2016-7290", "CVE-2016-7291", "CVE-2016-7277" );
	script_bugtraq_id( 94672, 94720, 94665, 94670, 94671, 94715 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-12-14 09:10:01 +0530 (Wed, 14 Dec 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Suite Multiple Vulnerabilities (3204068)" );
	script_tag( name: "summary", value: "This host is missing a critical update
  according to Microsoft Bulletin MS16-148." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - Microsoft Office software reads out of bound memory.

  - Office software fails to properly handle objects in memory.

  - Microsoft Office improperly validates input before loading libraries." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user, gain access
  to potentially sensitive information and take control of an affected system." );
	script_tag( name: "affected", value: "- Microsoft Office 2007 Service Pack 3

  - Microsoft Office 2010 Service Pack 2

  - Microsoft Office 2013 Service Pack 1

  - Microsoft Office 2016" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3127968" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3127986" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3128032" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3118380" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2889841" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3128020" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2883033" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms16-148" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer){
	exit( 0 );
}
commonpath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(!commonpath){
	exit( 0 );
}
if(IsMatchRegexp( officeVer, "^[12|14].*" )){
	filedirpath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
	if(filedirpath){
		for ver in make_list( "OFFICE12",
			 "OFFICE14" ) {
			msPath = filedirpath + "\\Microsoft Office\\" + ver;
			dllVer = fetch_file_version( sysPath: msPath, file_name: "Usp10.dll" );
			if(dllVer){
				if( version_in_range( version: dllVer, test_version: "1.0626.6002.00000", test_version2: "1.0626.6002.24029" ) ){
					VULN1 = TRUE;
					Vulnerable_range1 = "1.0626.6002.00000 - 1.0626.6002.24029";
				}
				else {
					if(version_in_range( version: dllVer, test_version: "1.0626.7601.00000", test_version2: "1.0626.7601.23584" )){
						VULN1 = TRUE;
						Vulnerable_range1 = "1.0626.7601.00000 - 1.0626.7601.23584";
					}
				}
			}
		}
	}
}
if(IsMatchRegexp( officeVer, "^[12|14|15|16].*" )){
	if(commonpath){
		for offsubver in make_list( "Office12",
			 "Office15",
			 "Office14",
			 "Office16" ) {
			offPath = commonpath + "\\Microsoft Shared\\" + offsubver;
			offexeVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
			if(offexeVer){
				if( IsMatchRegexp( offexeVer, "^12" ) ){
					Vulnerable_range2 = "12.0 - 12.0.6762.4999";
				}
				else {
					if( IsMatchRegexp( offexeVer, "^14" ) ){
						Vulnerable_range2 = "14.0 - 14.0.7177.4999";
					}
					else {
						if( IsMatchRegexp( offexeVer, "^15" ) ){
							Vulnerable_range2 = "15.0 - 15.0.4885.0999";
						}
						else {
							if(IsMatchRegexp( offexeVer, "^16" )){
								Vulnerable_range2 = "16.0 - 16.0.4471.0999";
							}
						}
					}
				}
				if(version_in_range( version: offexeVer, test_version: "12.0", test_version2: "12.0.6762.4999" ) || version_in_range( version: offexeVer, test_version: "14.0", test_version2: "14.0.7177.4999" ) || version_in_range( version: offexeVer, test_version: "15.0", test_version2: "15.0.4885.0999" ) || version_in_range( version: offexeVer, test_version: "16.0", test_version2: "16.0.4471.0999" )){
					report = "File checked:     " + offPath + "\\Mso.dll" + "\n" + "File version:     " + offexeVer + "\n" + "Vulnerable range: " + Vulnerable_range2 + "\n";
					security_message( data: report );
					exit( 0 );
				}
			}
		}
	}
}
if(VULN1){
	report = "File checked:     " + msPath + "Usp10.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range1 + "\n";
	security_message( data: report );
	exit( 0 );
}

