if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807062" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_cve_id( "CVE-2016-0037" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 22:03:00 +0000 (Wed, 08 May 2019)" );
	script_tag( name: "creation_date", value: "2016-02-10 08:15:01 +0530 (Wed, 10 Feb 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MS Active Directory Federation Services Denial of Service Vulnerability (3134222)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-020." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient
  validation of user supplied input by the Active Directory Federation
  Services (AD FS) during forms-based authentication." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause the server to become non-responsive, resulting in denial of
  service condition." );
	script_tag( name: "affected", value: "Active Directory Federation Services
  3.0 on Windows Server 2012 R2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3134222" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-020" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2012R2: 1 ) <= 0){
	exit( 0 );
}
adfs = registry_key_exists( key: "SOFTWARE\\Microsoft\\ADFS" );
if(!adfs){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
adfs_ver = fetch_file_version( sysPath: sysPath, file_name: "\\ADFS\\Microsoft.identityserver.dll" );
if(adfs_ver){
	if(version_is_less( version: adfs_ver, test_version: "6.3.9600.18192" )){
		report = "File checked:     " + sysPath + "\\ADFS\\Microsoft.identityserver.dll" + "\n" + "File version:     " + adfs_ver + "\n" + "Vulnerable range: Less than 6.3.9600.18192\n";
		security_message( data: report );
		exit( 0 );
	}
}

