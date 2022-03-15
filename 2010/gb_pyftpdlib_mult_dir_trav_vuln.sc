if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801616" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)" );
	script_cve_id( "CVE-2008-7262" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "pyftpdlib FTP Server Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/issues/detail?id=55" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "gb_pyftpdlib_detect.sc" );
	script_mandatory_keys( "pyftpdlib/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to retrieve or upload arbitrary
  system files." );
	script_tag( name: "affected", value: "ftpserver.py in pyftpdlib before 0.3.0" );
	script_tag( name: "insight", value: "The flaws exist because pyftpdlib allow remote authenticated users to access
  arbitrary files and directories via vectors involving a symlink in a pathname
  to a CWD, DELE, STOR, or RETR command." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to pyftpdlib version 0.5.2 or later." );
	script_tag( name: "summary", value: "This host is running pyftpdlib FTP server and is prone to multiple
  directory traversal vulnerabilities." );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/downloads/list" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "pyftpdlib/Ver" );
if(ver != NULL){
	if(version_is_less( version: ver, test_version: "0.3.0" )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "0.3.0" );
		security_message( port: 0, data: report );
	}
}

