CPE = "cpe:/a:southrivertech:titan_ftp_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902087" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-2425", "CVE-2010-2426" );
	script_bugtraq_id( 40949, 40904 );
	script_name( "Titan FTP Server 'XCRC' and 'COMB' Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40237" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59492" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/511839/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "gb_titan_ftp_detect.sc" );
	script_mandatory_keys( "TitanFTP/detected" );
	script_tag( name: "insight", value: "The flaws are due to

  - Input validation error when processing 'XCRC' commands, which can be
  exploited to determine the existence of a file outside the FTP root directory.

  - Input validation error when processing 'COMB' commands, which can be
  exploited to read and delete an arbitrary file." );
	script_tag( name: "solution", value: "Upgrade to Titan FTP Server 8.30.1231 or later." );
	script_tag( name: "summary", value: "This host is running Titan FTP Server and is prone to directory
  traversal vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to download
  arbitrary files and deletion of arbitrary files on the server." );
	script_tag( name: "affected", value: "Titan FTP Server version 8.10.1125 and prior." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "8.10.1125" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.30.1231" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

