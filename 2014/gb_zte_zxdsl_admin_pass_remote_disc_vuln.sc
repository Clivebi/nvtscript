if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804798" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-11-14 16:42:38 +0530 (Fri, 14 Nov 2014)" );
	script_name( "ZTE ZXDSL Modem /adminpasswd.cgi Admin Password Remote Disclosure Vulnerability" );
	script_cve_id( "CVE-2014-9184", "CVE-2014-9183" );
	script_tag( name: "summary", value: "This host is installed with ZTE ZXDSL
  Modem and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read admin password or not." );
	script_tag( name: "insight", value: "Flaw is due to the source information of
  /adminpasswd.cgi script displays admin password information in cleartext." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to admin password information." );
	script_tag( name: "affected", value: "ZTE ZXDSL 831CI Modem" );
	script_tag( name: "solution", value: "No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2014/Nov/40" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35203" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/533929/30/0/threaded" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
http_port = http_get_port( default: 80 );
if(http_vuln_check( port: http_port, url: "/adminpasswd.cgi", check_header: TRUE, pattern: ">Admin account.*configuration of your ADSL<", extra_check: make_list( ">User Name:<",
	 ">New Password:<",
	 ">Admin Account<",
	 "btnApplyAdmin" ) )){
	security_message( http_port );
	exit( 0 );
}

