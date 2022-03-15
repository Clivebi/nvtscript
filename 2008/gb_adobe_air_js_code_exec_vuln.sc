if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800065" );
	script_version( "2020-04-14T08:15:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-14 08:15:28 +0000 (Tue, 14 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5108" );
	script_bugtraq_id( 32334 );
	script_name( "Adobe AIR JavaScript Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Remote exploitation could lead to unauthorized disclosure of
  information, modification of files, and disruption of service." );
	script_tag( name: "affected", value: "Adobe AIR 1.1 and earlier on Windows." );
	script_tag( name: "insight", value: "The issue is due to improper sanitization of Javascript in the
  application." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Adobe AIR 1.5." );
	script_tag( name: "summary", value: "This host has Adobe AIR installed, and is prone to privilege
  escalation vulnerability." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
if(!( get_kb_item( "SMB/WindowsVersion" ) )){
	exit( 0 );
}
airVer = registry_get_sz( item: "DisplayVersion", key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Adobe AIR" );
if(airVer){
	if(version_is_less( version: airVer, test_version: "1.5.0.7220" )){
		report = report_fixed_ver( installed_version: airVer, fixed_version: "1.5.0.7220" );
		security_message( port: 0, data: report );
	}
}

