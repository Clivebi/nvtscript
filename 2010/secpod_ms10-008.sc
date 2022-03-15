if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900229" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0252" );
	script_name( "Microsoft Data Analyzer ActiveX Control Vulnerability (978262)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0341" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-008" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attackers execute arbitrary code
  and can compromise a vulnerable system." );
	script_tag( name: "affected", value: "- Microsoft Windows 7

  - Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "An unspecified error exists in the Microsoft Data Analyzer ActiveX control
  (max3activex.dll) when used with Internet Explorer. Attackers can execute
  arbitrary code by tricking a user into visiting a specially crafted web page." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-008." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information.

  Workaround:
  Set the killbit for the following CLSIDs,
  {E0ECA9C3-D669-4EF4-8231-00724ED9288F}, {C05A1FBC-1413-11D1-B05F-00805F4945F6},
  {5D80A6D1-B500-47DA-82B8-EB9875F85B4D}, {0CCA191D-13A6-4E29-B746-314DEE697D83},
  {2d8ed06d-3c30-438b-96ae-4d110fdc1fb8}" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/240797" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_activex.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, winVista: 3, win2008: 3, win7: 1 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "978262" ) == 0){
	exit( 0 );
}
clsids = make_list( "{E0ECA9C3-D669-4EF4-8231-00724ED9288F}",
	 "{C05A1FBC-1413-11D1-B05F-00805F4945F6}",
	 "{5D80A6D1-B500-47DA-82B8-EB9875F85B4D}",
	 "{0CCA191D-13A6-4E29-B746-314DEE697D83}",
	 "{2d8ed06d-3c30-438b-96ae-4d110fdc1fb8}" );
for clsid in clsids {
	if(is_killbit_set( clsid: clsid ) == 0){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

