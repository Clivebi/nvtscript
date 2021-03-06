CPE = "cpe:/a:ipswitch:ws_ftp_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900451" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-5692", "CVE-2008-5693" );
	script_bugtraq_id( 27654 );
	script_name( "WS_FTP Server Manager Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "secpod_wsftp_win_detect.sc" );
	script_mandatory_keys( "ipswitch/ws_ftp_server/detected" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in the
  compressed rar archive and can cause memory corruption or buffer overflows." );
	script_tag( name: "affected", value: "Ipswitch WS_FTP Server version 6.1.0.0 and prior versions." );
	script_tag( name: "insight", value: "This flaw is due to

  - an error within the WS_FTP Server Manager when processing HTTP requests for
    the FTPLogServer/LogViewer.asp script.

  - less access control in custom ASP Files in WSFTPSVR/ via a request with the
    appended dot characters which causes disclosure of .asp file contents." );
	script_tag( name: "solution", value: "Upgrade to the latest version 6.1.1 or later." );
	script_tag( name: "summary", value: "This host is installed with WS_FTP Server and is prone to Security
  Bypass Vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/28822" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/wsftpweblog-adv.txt" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "6.1.0.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.1.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

