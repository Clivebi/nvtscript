if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801617" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)" );
	script_cve_id( "CVE-2007-6736", "CVE-2007-6737", "CVE-2007-6739", "CVE-2007-6740", "CVE-2007-6741" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "pyftpdlib FTP Server Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/issues/detail?id=3" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/issues/detail?id=9" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/issues/detail?id=11" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/issues/detail?id=20" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/issues/detail?id=25" );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "gb_pyftpdlib_detect.sc" );
	script_mandatory_keys( "pyftpdlib/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to retrieve or upload arbitrary
  system files or cause a denial of service." );
	script_tag( name: "affected", value: "ftpserver.py in pyftpdlib before 0.2.0" );
	script_tag( name: "insight", value: "Multiple flaws exist because pyftpdlib,

  - allows remote authenticated users to access arbitrary files and directories
    via a .. (dot dot) in a LIST, STOR, or RETR command.

  - does not increment the attempted_logins count for a USER command that
    specifies an invalid username, which makes it easier for remote attackers
    to obtain access via a brute-force attack.

  - allows remote attackers to cause a denial of service via a long command.

  - does not limit the number of attempts to discover a unique filename, which
    might allow remote authenticated users to cause a denial of service via
    a STOU command.

  - does not prevent TCP connections to privileged ports if the destination IP
    address matches the source IP address of the connection from the FTP client,
    which might allow remote authenticated users to conduct FTP bounce attacks
    via crafted FTP data." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to pyftpdlib version 0.5.2 or later." );
	script_tag( name: "summary", value: "This host is running pyftpdlib FTP server and is prone to multiple
  vulnerabilities." );
	script_xref( name: "URL", value: "http://code.google.com/p/pyftpdlib/downloads/list" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "pyftpdlib/Ver" );
if(ver != NULL){
	if(version_is_less( version: ver, test_version: "0.2.0" )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "0.2.0" );
		security_message( port: 0, data: report );
	}
}

