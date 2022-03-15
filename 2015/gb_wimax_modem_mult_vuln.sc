if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806799" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "9.7" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-12-15 09:04:51 +0530 (Tue, 15 Dec 2015)" );
	script_name( "WIMAX Modem Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/38914" );
	script_tag( name: "summary", value: "This host is installed with WIMAX Modem
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to retrieve sensitive information or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The '/cgi-bin/diagnostic.cgi' which fails to properly restrict access.

  - The '/cgi-bin/pw.cgi' which fails to properly restrict access." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read sensitive information and set it on his own modem and
  send a packet to the modem for crashing/downgrading/DOS and to obtain the
  control of similar modem in order to launch DOS or DDOS attacks on targets." );
	script_tag( name: "affected", value: "WIMAX MT711x version V_3_11_14_9_CPE" );
	script_tag( name: "solution", value: "No known solution was made available for
  at least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
wimaxPort = http_get_port( default: 80 );
url = NASLString( "/cgi-bin/multi_wifi.cgi" );
req = http_get( item: url, port: wimaxPort );
res = http_send_recv( port: wimaxPort, data: req );
if(ContainsString( res, "SeowonCPE" ) && ContainsString( res, "wifi_mode" ) && ContainsString( res, "auth_mode" ) && ContainsString( res, "network_key" ) && ContainsString( res, "w_ssid" ) && ContainsString( res, "wifi_setup" ) && ContainsString( res, ">WiMAX" )){
	report = http_report_vuln_url( port: wimaxPort, url: url );
	security_message( port: wimaxPort, data: report );
	exit( 0 );
}

