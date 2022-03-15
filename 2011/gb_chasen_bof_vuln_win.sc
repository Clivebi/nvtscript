if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802343" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_cve_id( "CVE-2011-4000" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-11-09 16:19:55 +0530 (Wed, 09 Nov 2011)" );
	script_name( "ChaSen Buffer Overflow Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN16901583/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000099.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to cause a buffer overflow
  or execute arbitrary code." );
	script_tag( name: "affected", value: "ChaSen Version 2.4.x" );
	script_tag( name: "insight", value: "The flaw is due to an error when reading user-supplied input string,
  which allows attackers to execute arbitrary code via a crafted string." );
	script_tag( name: "solution", value: "Use ChaSen Version 2.3.3." );
	script_tag( name: "summary", value: "The host is running ChaSen Software and is prone to buffer
  overflow vulnerability" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://chasen.naist.jp/hiki/ChaSen/" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\chasen";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
chaName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( chaName, "ChaSen" )){
	chaVer = eregmatch( pattern: "ChaSen ([0-9.]+)", string: chaName );
	if(chaVer[1] != NULL){
		if(version_in_range( version: chaVer[1], test_version: "2.4.0", test_version2: "2.4.4" )){
			report = report_fixed_ver( installed_version: chaVer[1], vulnerable_range: "2.4.0 - 2.4.4" );
			security_message( port: 0, data: report );
		}
	}
}

