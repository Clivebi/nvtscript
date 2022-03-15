if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811927" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11762", "CVE-2017-8694", "CVE-2017-8717", "CVE-2017-11763", "CVE-2017-11765", "CVE-2017-8718", "CVE-2017-8727", "CVE-2017-11815", "CVE-2017-11771", "CVE-2017-11772", "CVE-2017-11779", "CVE-2017-11780", "CVE-2017-11781", "CVE-2017-11784", "CVE-2017-11785", "CVE-2017-11790", "CVE-2017-11793", "CVE-2017-11810", "CVE-2017-11816", "CVE-2017-11817", "CVE-2017-11818", "CVE-2017-11824", "CVE-2017-11814", "CVE-2017-13080" );
	script_bugtraq_id( 101108, 101100, 101161, 101109, 101111, 101162, 101142, 101114, 101116, 101166, 101110, 101140, 101147, 101149, 101077, 101141, 101081, 101094, 101095, 101101, 101099, 101093, 101136, 101274 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-10-11 08:59:57 +0530 (Wed, 11 Oct 2017)" );
	script_name( "Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4041690)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4041690" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A spoofing vulnerability in the Windows implementation of wireless networking (KRACK)

  - An error in USBHUB.SYS randomly causes memory corruption that results in
    random system crashes that are extremely difficult to diagnose.

  - Security updates to Microsoft Windows Search Component, Windows kernel-mode drivers,
    Microsoft Graphics Component, Internet Explorer, Windows kernel, Windows Wireless
    Networking, Windows Storage and File systems, Microsoft Windows DNS, Microsoft JET
    Database Engine, and the Windows SMB Server." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the security context of the local system to take
  complete control of an affected system, gain access to potentially sensitive
  information, conduct a denial-of-service condition, bypass certain security
  restrictions and gain elevated privileges." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2012." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4041690" );
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
fileVer = fetch_file_version( sysPath: sysPath, file_name: "shell32.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.2.9200.22281" )){
	report = "File checked:     " + sysPath + "\\shell32.dll" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range:  Less than 6.2.9200.22281\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

