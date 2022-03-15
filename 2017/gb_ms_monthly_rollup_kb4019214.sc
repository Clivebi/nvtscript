if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811112" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-0064", "CVE-2017-0077", "CVE-2017-0171", "CVE-2017-0190", "CVE-2017-0213", "CVE-2017-0214", "CVE-2017-0220", "CVE-2017-0222", "CVE-2017-0226", "CVE-2017-0238", "CVE-2017-0245", "CVE-2017-0246", "CVE-2017-0258", "CVE-2017-0263", "CVE-2017-0267", "CVE-2017-0268", "CVE-2017-0269", "CVE-2017-0270", "CVE-2017-0271", "CVE-2017-0272", "CVE-2017-0273", "CVE-2017-0274", "CVE-2017-0275", "CVE-2017-0276", "CVE-2017-0277", "CVE-2017-0278", "CVE-2017-0279", "CVE-2017-0280" );
	script_bugtraq_id( 98114, 98115, 98112, 98111, 98097, 98274, 98273, 98298, 98271, 98270, 98272, 98259, 98258, 98237, 98108, 98121, 98127, 98103, 98102, 98260, 98261, 98263, 98264, 98265, 98266, 98267, 98268, 98139 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-10 11:57:51 +0530 (Wed, 10 May 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows Monthly Rollup (KB4019214)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update (monthly rollup) according to microsoft KB4019214" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This security update includes quality
  and security improvements in Microsoft Graphics Component, Windows COM,
  Windows Server, Windows Kernel and Microsoft Windows DNS" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute code or elevate user privileges, take control of the affected system,
  and access information from one domain and inject it into another domain, bypass
  security restrictions, conduct denial-of-service condition and gain access to
  potentially sensitive information." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2012." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4019214" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2012: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
gdiVer = fetch_file_version( sysPath: sysPath, file_name: "Ole32.dll" );
if(!gdiVer){
	exit( 0 );
}
if(version_is_less( version: gdiVer, test_version: "6.2.9200.22141" )){
	report = "File checked:     " + sysPath + "\\Ole32.dll" + "\n" + "File version:     " + gdiVer + "\n" + "Vulnerable range: Less than 6.2.9200.22141\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

