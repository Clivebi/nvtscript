if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801992" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)" );
	script_cve_id( "CVE-2010-4871" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "SmartFTP Filename Processing Unspecified Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42060" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/63113" );
	script_xref( name: "URL", value: "https://www.smartftp.com/forums/index.php?/topic/16425-smartftp-client-40-change-log/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "secpod_smartftp_client_detect.sc" );
	script_mandatory_keys( "SmartFTP/Client/Ver" );
	script_tag( name: "insight", value: "An unspecified flaw exists in SmartFTP when processing filenames, has an
  unknown impact and attack vector." );
	script_tag( name: "solution", value: "Update SmartFTP Client to version 4.0 Build 1142 or later." );
	script_tag( name: "summary", value: "This host is installed with SmartFTP Client and is prone to
  unspecified vulnerability." );
	script_tag( name: "impact", value: "Has an unknown impact and attack vector." );
	script_tag( name: "affected", value: "SmartFTP Client version prior to 4.0.1142.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.smartftp.com/download/" );
	exit( 0 );
}
require("version_func.inc.sc");
sftpVer = get_kb_item( "SmartFTP/Client/Ver" );
if(sftpVer != NULL){
	if(version_is_less( version: sftpVer, test_version: "4.0.1142.0" )){
		report = report_fixed_ver( installed_version: sftpVer, fixed_version: "4.0.1142.0" );
		security_message( port: 0, data: report );
	}
}

