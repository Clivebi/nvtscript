if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801614" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)" );
	script_cve_id( "CVE-2009-5010" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "pyftpdlib FTP Server Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/issues/detail?id=91" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/source/detail?r=439" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "gb_pyftpdlib_detect.sc" );
	script_mandatory_keys( "pyftpdlib/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a denial of service." );
	script_tag( name: "affected", value: "ftpserver.py in pyftpdlib before 0.5.1" );
	script_tag( name: "insight", value: "The flaw is due to race condition in the FTPHandler class, which allows
  remote attackers to cause a denial of service by establishing and then
  immediately closing a TCP connection, leading to the accept function having
  an unexpected return value of None." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to pyftpdlib version 0.5.2 or later." );
	script_tag( name: "summary", value: "This host is running pyftpdlib FTP server and is prone to Denial of
  Service vulnerability." );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/downloads/list" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "pyftpdlib/Ver" );
if(ver != NULL){
	if(version_is_less( version: ver, test_version: "0.5.1" )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "0.5.1" );
		security_message( port: 0, data: report );
	}
}

