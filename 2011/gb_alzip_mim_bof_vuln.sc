if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802120" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_cve_id( "CVE-2011-1336" );
	script_bugtraq_id( 48493 );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "ALZip MIM File Processing Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "This host has ALZip installed and is prone to a buffer overflow
  vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to an error in libETC.dll when processing the
  'filename' field within MIM files." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code in the
  context of the application. Failed attacks will cause denial-of-service conditions." );
	script_tag( name: "affected", value: "ALZip version 8.21 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 8.21 published after June 29th, 2011." );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000048.html" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\ESTsoft\\ALZip";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
if(!version = registry_get_sz( key: key, item: "Version" )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "8.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Version 8.21 published after June 29th, 2011." );
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less than or equal to 8.12" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

