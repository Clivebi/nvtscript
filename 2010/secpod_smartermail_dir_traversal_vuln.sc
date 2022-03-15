CPE = "cpe:/a:smartertools:smartermail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902259" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)" );
	script_cve_id( "CVE-2010-3486" );
	script_bugtraq_id( 43324 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "SmarterMail Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61910" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15048/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1009-exploits/smartermail-traversal.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_smartermail_detect.sc" );
	script_require_ports( "Services/www", 80, 9998 );
	script_mandatory_keys( "SmarterMail/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote authenticated users to
  read and write directories, files and perform malicious operations." );
	script_tag( name: "affected", value: "SmarterTools SmarterMail 7.1.3876" );
	script_tag( name: "insight", value: "The flaw is due to error in the 'FileStorageUpload.ashx', which
  fails to validate the input value passed to the 'name' parameter. This allows
  remote attackers to read arbitrary files via a '../' or '%5C' or '%255c' in the
  name parameter." );
	script_tag( name: "summary", value: "This host is running SmarterMail and is prone to directory
  traversal vulnerability." );
	script_tag( name: "solution", value: "Upgrade to version 7.2.3925 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.smartertools.com/smartermail/mail-server-software.aspx" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "7.1.3876" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.2.3925" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

