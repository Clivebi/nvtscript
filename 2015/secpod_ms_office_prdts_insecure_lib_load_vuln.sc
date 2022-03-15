if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902254" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_cve_id( "CVE-2010-3141", "CVE-2010-3142", "CVE-2010-3146", "CVE-2010-3148" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-09-09 10:16:10 +0530 (Wed, 09 Sep 2015)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Office Products Insecure Library Loading Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with microsoft
  product(s) and is prone to insecure library loading vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the application
  insecurely loading certain libraries from the current working directory,
  which could allow attackers to execute arbitrary code by tricking a user into
  opening a file from a network share." );
	script_tag( name: "impact", value: "Successful exploitation will allow the
  attackers to execute arbitrary code and conduct DLL hijacking attacks." );
	script_tag( name: "affected", value: "- Microsoft Visio 2003

  - Microsoft Office Groove 2007

  - Microsoft Office PowerPoint 2007/2010" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14723/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14782/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14746/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14744/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2188" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2192" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "secpod_office_products_version_900032.sc", "secpod_ms_office_detection_900025.sc" );
	script_mandatory_keys( "MS/Office/Ver", "MS/Office/Prdts/Installed" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-055" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer){
	exit( 0 );
}
ver = get_kb_item( "SMB/Office/PowerPnt/Version" );
if( ver && ( IsMatchRegexp( ver, "^(12|14)\\..*" ) ) ){
	if(version_in_range( version: ver, test_version: "14.0", test_version2: "14.0.4760.1000" ) || version_in_range( version: ver, test_version: "12.0", test_version2: "12.0.6535.5002" )){
		VULN = TRUE;
		fix = "Apply the patch";
	}
}
else {
	if(ver = get_kb_item( "SMB/Office/Groove/Version" )){
		if(ver && ( IsMatchRegexp( ver, "^12\\..*" ) )){
			if(version_is_less( version: ver, test_version: "12.0.6550.5004" )){
				VULN = TRUE;
				fix = "12.0.6550.5004";
			}
		}
	}
}
if(VULN){
	report = "Installed version: " + ver + "\n" + "Fixed version: " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}
if(ovPath = registry_get_sz( item: "Path", key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\visio.exe" )){
	offPath = ovPath - "\\Visio11" + "OFFICE11";
	ver = fetch_file_version( sysPath: offPath, file_name: "Omfc.dll" );
	if(ver && ( IsMatchRegexp( ver, "^11\\..*" ) )){
		if(version_is_less( version: ver, test_version: "11.0.8332.0" )){
			VULN = TRUE;
			fix = "11.0.8332.0";
		}
	}
}
if(VULN){
	report = "Installed version: " + ver + "\n" + "Fixed version: " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

