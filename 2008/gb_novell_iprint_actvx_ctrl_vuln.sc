if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800070" );
	script_version( "2020-04-27T11:01:03+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 11:01:03 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5231" );
	script_name( "Novell iPrint ActiveX control Stack-based BOF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary code via a long target
  frame option value, which crashes the browser and may allow code execution." );
	script_tag( name: "affected", value: "Novell iPrint Client version 5.06 and prior on Windows." );
	script_tag( name: "insight", value: "The issue is due to the improper handling of user requests sent to the
  ExecuteRequest method in ienipp.ocx file." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Novell iPrint Client version 5.06 is obsoleted, Upgrade to
  Novell iPrint Client version higher than 5.06." );
	script_tag( name: "summary", value: "The host is installed with Novell iPrint, and is prone to stack
  based buffer overflow vulnerability." );
	script_xref( name: "URL", value: "http://download.novell.com/index.jsp" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
iPrintVer = registry_get_sz( key: "SOFTWARE\\Novell-iPrint", item: "Current Version" );
if(!iPrintVer){
	exit( 0 );
}
novVer = eregmatch( pattern: "v([0-9.]+)", string: iPrintVer );
if(novVer[1] != NULL){
	if(version_is_less_equal( version: novVer[1], test_version: "5.06" )){
		report = report_fixed_ver( installed_version: novVer[1], vulnerable_range: "Less than or equal to 5.06" );
		security_message( port: 0, data: report );
	}
}

