if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900110" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_bugtraq_id( 30615 );
	script_cve_id( "CVE-2008-3515", "CVE-2008-3516" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Web application abuses" );
	script_name( "Adobe Presenter viewer.swf and loadflash.js XSS Vulnerability" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31432/" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2322" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb08-17.html" );
	script_tag( name: "summary", value: "The host is running Adobe Presenter, which is prone to input
  validation errors which can be exploited by malicious people to conduct cross-site scripting vulnerability." );
	script_tag( name: "insight", value: "Input validation errors in the 'viewer.swf' and 'loadflash.js' files,
  which could be exploited by attackers to execute arbitrary scripting code in the user's browser session." );
	script_tag( name: "affected", value: "Adobe Presenter 6.x and 7.x." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Adobe Presenter 7.0.1." );
	script_tag( name: "impact", value: "Execution of arbitrary HTML or Scripting code in the security
  context of the affected web site." );
	exit( 0 );
}
require("smb_nt.inc.sc");
if(!( get_kb_item( "SMB/WindowsVersion" ) )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Adobe\\Presenter" )){
	exit( 0 );
}
adobeVer = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Adobe Presenter 6", item: "DisplayVersion" );
if(!adobeVer){
	adobeVer = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Adobe Presenter 7", item: "DisplayVersion" );
	if(!adobeVer){
		exit( 0 );
	}
}
if(egrep( pattern: "^(6\\..*|7\\.0)$", string: adobeVer )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

