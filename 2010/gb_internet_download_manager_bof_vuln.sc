if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800776" );
	script_version( "2020-03-04T08:41:18+0000" );
	script_tag( name: "last_modification", value: "2020-03-04 08:41:18 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)" );
	script_cve_id( "CVE-2010-0995" );
	script_bugtraq_id( 39822 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Internet Download Manager FTP Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39446" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2010-62/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/511060/100/0/threaded" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw exists due to boundary error when sending certain test sequences to
  an 'FTP' server, which leads a stack-based buffer overflow by tricking a user
  into downloading a file from a specially crafted FTP URI." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the Internet Download Manager 5.19." );
	script_tag( name: "summary", value: "This host is installed with Internet Download Manager and is prone
  to a buffer overflow vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Internet Download Manager version prior to 5.19." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Internet Download Manager";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
idmName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( idmName, "Internet Download Manager" )){
	idmPath = registry_get_sz( key: key, item: "DisplayIcon" );
	if(idmPath){
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: idmPath );
		fire = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: idmPath );
		idmVer = GetVer( file: fire, share: share );
		if(idmVer){
			if(version_is_less( version: idmVer, test_version: "5.19.2.1" )){
				report = report_fixed_ver( installed_version: idmVer, fixed_version: "5.19.2.1", file_checked: idmPath );
				security_message( port: 0, data: report );
			}
		}
	}
}
exit( 99 );

