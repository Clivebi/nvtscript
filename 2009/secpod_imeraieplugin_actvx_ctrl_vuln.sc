if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900520" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-23 08:26:42 +0100 (Mon, 23 Mar 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0813" );
	script_bugtraq_id( 33993 );
	script_name( "Imera TeamLinks ImeraIEPlugin.dll ActiveX Control DoS Vulnerability" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/8144" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49028" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2009/Mar/0086.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Attacker may exploit this issue to download and execute arbitrary script code
  on the victim's system by passing malicious URLs and may crash the application." );
	script_tag( name: "affected", value: "Imera Systems ImeraIEPlugin.dll version 1.0.2.54 on Windows." );
	script_tag( name: "insight", value: "This issue is caused by errors in the ImeraIEPlugin.dll control while
  processing the URLs passed into DownloadProtocol, DownloadHost, DownloadPort
  and DownloadURI parameters." );
	script_tag( name: "summary", value: "This host is installed with Imera ImeraIEPlugin ActiveX and
  is prone to denial of service vulnerability." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_activex.inc.sc");
require("secpod_smb_func.inc.sc");
imeraName = registry_get_sz( key: "SOFTWARE\\ImeraIBCPilot", item: "Name" );
if(ContainsString( imeraName, "Imera TeamLinks" )){
	imeraPath = registry_get_sz( key: "SOFTWARE\\ImeraIBCPilot", item: "Install_Dir" );
	if(imeraPath == NULL){
		exit( 0 );
	}
}
imeraPath = imeraPath + "\\ImeraIEPlugin\\ImeraIEPlugin.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: imeraPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: imeraPath );
imeradllVer = GetVer( share: share, file: file );
if(imeradllVer != NULL){
	if(version_is_less_equal( version: imeradllVer, test_version: "1.0.2.54" )){
		if(is_killbit_set( clsid: "{75CC8584-86D4-4A50-B976-AA72618322C6}" ) == 0){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

