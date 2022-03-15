if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900109" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_cve_id( "CVE-2008-3676" );
	script_bugtraq_id( 30663 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_name( "hMailServer IMAP Denial of Service Vulnerability" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/495361" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31480/" );
	script_xref( name: "URL", value: "http://www.hmailserver.com/?page=download_mirrors&downloadid=144" );
	script_tag( name: "summary", value: "This host is running hMailServer, which is prone to
  Denial of Service vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to an error in the mail server that can be exploited
  by sending large numbers of IMAP commands." );
	script_tag( name: "affected", value: "hMailServer version 4.4.1 - Build 273 and prior" );
	script_tag( name: "solution", value: "Fixed in development version 4.4.2 (build 279)." );
	script_tag( name: "impact", value: "Exploitation will cause the server to crash and deny access
  to legitimate users." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\hMailServer_is1";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
hmsVer = registry_get_sz( key: key, item: "DisplayName" );
if(!hmsVer){
	exit( 0 );
}
if(egrep( pattern: "hMailServer ([0-3]\\..*|4\\.([0-3]\\..*|4\\.[01]))", string: hmsVer )){
	report = report_fixed_ver( installed_version: hmsVer, fixed_version: "4.4.2 (build 279)" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

