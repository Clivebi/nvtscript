if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812228" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_cve_id( "CVE-2017-16953" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-28 02:29:00 +0000 (Thu, 28 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-11-28 18:25:42 +0530 (Tue, 28 Nov 2017)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "ZTE ZXDSL 831CII Access Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ZTE ZXDSL 831CII
  router and is prone to access bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to obtain sensitive information or not." );
	script_tag( name: "insight", value: "The flaw is due to an improper access
  restriction on CGI files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to modify router PPPoE configurations, setup malicious
  configurations which later could lead to disrupt network & its activities." );
	script_tag( name: "affected", value: "ZTE ZXDSL 831CII" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/43188" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/43188" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc", "gb_zte_zxdsl_831CII_telnet_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
zteport = http_get_port( default: 80 );
if(!teldetect = get_kb_item( "ZXDSL_831CII/Installed" )){
	banner = http_get_remote_headers( port: zteport );
	if(!banner || !ContainsString( banner, "WWW-Authenticate: Basic realm=\"DSL Router\"" )){
		exit( 0 );
	}
}
url = "/connoppp.cgi";
if(http_vuln_check( port: zteport, url: url, check_header: TRUE, pattern: "Your DSL router is.*", extra_check: "Configure it from the.*vpivci.cgi'>Quick.*Setup<" )){
	if(http_vuln_check( port: zteport, url: "/vpivci.cgi", check_header: TRUE, pattern: "Please enter VPI and VCI numbers for the Internet connection which is provided", extra_check: make_list( "configure your DSL Router",
		 "VPI:",
		 "VCI:" ) )){
		report = http_report_vuln_url( port: zteport, url: url );
		security_message( port: zteport, data: report );
		exit( 0 );
	}
}

