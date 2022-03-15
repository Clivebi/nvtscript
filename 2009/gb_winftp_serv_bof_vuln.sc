if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800346" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-02-04 15:43:54 +0100 (Wed, 04 Feb 2009)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0351" );
	script_bugtraq_id( 33454 );
	script_name( "WinFTP Server LIST Command Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_winftp_serv_detect.sc" );
	script_mandatory_keys( "WinFTP/Server/Ver" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7875" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/48263" );
	script_tag( name: "impact", value: "Allows remote authenticated attackers to execute arbitrary code within the
  context of the affected application resulting in buffer overflow and can cause
  denial of service condition." );
	script_tag( name: "affected", value: "WinFTP Server version 2.3.0 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw exists when processing malformed arguments passed to the LIST command
  with an asterisk (*) character." );
	script_tag( name: "solution", value: "Upgrade to WinFTP Server version 3.5.0 or later." );
	script_tag( name: "summary", value: "This host is running WinFTP Server and is prone to Buffer Overflow
  vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
winFtpVer = get_kb_item( "WinFTP/Server/Ver" );
if(!winFtpVer){
	exit( 0 );
}
if(version_is_less_equal( version: winFtpVer, test_version: "2.3.0.0" )){
	report = report_fixed_ver( installed_version: winFtpVer, vulnerable_range: "Less than or equal to 2.3.0.0" );
	security_message( port: 0, data: report );
}
exit( 0 );

