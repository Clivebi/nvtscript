if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811111" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_cve_id( "CVE-2017-0064", "CVE-2017-0077", "CVE-2017-0190", "CVE-2017-0212", "CVE-2017-0213", "CVE-2017-0214", "CVE-2017-0222", "CVE-2017-0226", "CVE-2017-0227", "CVE-2017-0228", "CVE-2017-0229", "CVE-2017-0231", "CVE-2017-0233", "CVE-2017-0234", "CVE-2017-0236", "CVE-2017-0238", "CVE-2017-0240", "CVE-2017-0241", "CVE-2017-0246", "CVE-2017-0248", "CVE-2017-0258", "CVE-2017-0259", "CVE-2017-0263", "CVE-2017-0267", "CVE-2017-0268", "CVE-2017-0269", "CVE-2017-0270", "CVE-2017-0271", "CVE-2017-0272", "CVE-2017-0273", "CVE-2017-0274", "CVE-2017-0275", "CVE-2017-0276", "CVE-2017-0277", "CVE-2017-0278", "CVE-2017-0279", "CVE-2017-0280" );
	script_bugtraq_id( 98121, 98114, 98298, 98099, 98102, 98103, 98127, 98139, 98281, 98164, 98217, 98173, 98179, 98229, 98234, 98237, 98203, 98208, 98108, 98117, 98112, 98113, 98258, 98259, 98261, 98263, 98264, 98265, 98260, 98274, 98266, 98267, 98268, 98270, 98271, 98272, 98273 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-10 08:55:53 +0530 (Wed, 10 May 2017)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4019474)" );
	script_tag( name: "summary", value: "This host is missing important/critical
  security update according to Microsoft Security update KB4019474." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system, execute
  arbitrary code in the context of the current user, gain the same user rights as
  the current user, could take control of an affected system, spoof content, bypass
  certain security restrictions and cause a host machine to crash." );
	script_tag( name: "affected", value: "Microsoft Windows 10 x32/x64." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-gb/help/4019474" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
edgeVer = fetch_file_version( sysPath: sysPath, file_name: "Edgehtml.dll" );
if(!edgeVer){
	exit( 0 );
}
if(version_is_less( version: edgeVer, test_version: "11.0.10240.17394" )){
	report = "File checked:     " + sysPath + "\\Edgehtml.dll" + "\n" + "File version:     " + edgeVer + "\n" + "Vulnerable range: Less than 11.0.10240.17394\n";
	security_message( data: report );
	exit( 0 );
}
