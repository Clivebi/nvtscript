if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801491" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2011-01-10 14:22:58 +0100 (Mon, 10 Jan 2011)" );
	script_bugtraq_id( 28606 );
	script_cve_id( "CVE-2008-1086" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft 'hxvz.dll' ActiveX Control Memory Corruption Vulnerability (948881)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/41464" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Apr/1019800.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-023" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attackers execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 2 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'hxvz.dll' ActiveX control." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-023." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information.

  Workaround:

  Set the killbit for the following CLSIDs,
  {314111b8-a502-11d2-bbca-00c04f8ec294}, {314111c6-a502-11d2-bbca-00c04f8ec294}" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_activex.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "948881" ) == 0){
	exit( 0 );
}
clsids = make_list( "{314111b8-a502-11d2-bbca-00c04f8ec294}",
	 "{314111c6-a502-11d2-bbca-00c04f8ec294}" );
for clsid in clsids {
	if(is_killbit_set( clsid: clsid ) == 0){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

