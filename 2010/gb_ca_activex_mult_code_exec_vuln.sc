if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801225" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)" );
	script_bugtraq_id( 40689, 40494 );
	script_cve_id( "CVE-2010-2193" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Computer Associates WebScan ActiveX Control Multiple Remote Code Execution Vulnerabilities" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-034" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/511764/100/0/threaded" );
	script_xref( name: "URL", value: "https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=238635" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attackers execute
arbitrary code and can compromise a vulnerable system." );
	script_tag( name: "affected", value: "PSFormX ActiveX control with CLSID
{56393399-041A-4650-94C7-13DFCB1F4665} WebScan ActiveX control with CLSID
{7B297BFD-85E4-4092-B2AF-16A91B2EA103}" );
	script_tag( name: "insight", value: "Multiple unspecified errors in the CA PSFormX and WebScan
ActiveX controls, allow remote attackers to execute arbitrary code via unknown
vectors." );
	script_tag( name: "summary", value: "This host is installed with CA PSFormX or WebScan ActiveX
controls and is prone to multiple remote code execution vulnerabilities." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_activex.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
clsids = make_list( "{56393399-041A-4650-94C7-13DFCB1F4665}",
	 "{7B297BFD-85E4-4092-B2AF-16A91B2EA103}" );
for clsid in clsids {
	if(is_killbit_set( clsid: clsid ) == 0){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

