if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902171" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)" );
	script_cve_id( "CVE-2009-4775" );
	script_bugtraq_id( 36297 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Ipswitch WS_FTP Professional 'HTTP' Response Format String Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9607" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53098" );
	script_xref( name: "URL", value: "http://www.juniper.net/security/auto/vulnerabilities/vuln36297.html" );
	script_xref( name: "URL", value: "http://www.packetstormsecurity.org/0909-exploits/nocoolnameforawsftppoc.pl.txt" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "secpod_ws_ftp_client_detect.sc" );
	script_mandatory_keys( "Ipswitch/WS_FTP_Pro/Client/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code in
  the context of the vulnerable application, failed exploit attempts will likely
  result in a denial-of-service condition." );
	script_tag( name: "affected", value: "WS_FTP Professional version prior to 12.2" );
	script_tag( name: "insight", value: "The flaw is due to error in 'formatted-printing()' function. It fails to
  properly sanitize user supplied input before passing it as the format
  specifier. Specifically, the issue presents itself when the client parses
  specially crafted responses for a malicious HTTP server." );
	script_tag( name: "solution", value: "Upgrade to WS_FTP Professional version 12.2." );
	script_tag( name: "summary", value: "This host is installed with WS_FTP professinal client and is prone to
  format string vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.ipswitchft.com/Individual/Products/Ws_Ftp_Pro/" );
	exit( 0 );
}
require("version_func.inc.sc");
wsftpVer = get_kb_item( "Ipswitch/WS_FTP_Pro/Client/Ver" );
if(isnull( wsftpVer )){
	exit( 0 );
}
if(version_is_less( version: wsftpVer, test_version: "12.2" )){
	report = report_fixed_ver( installed_version: wsftpVer, fixed_version: "12.2" );
	security_message( port: 0, data: report );
}

