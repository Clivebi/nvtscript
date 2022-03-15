if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803720" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-25 12:51:19 +0530 (Tue, 25 Jun 2013)" );
	script_name( "TRENDnet Print Server Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/26401" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/trendnet-te100-p1u-authentication-bypass" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw is due to a failure of the application to validate
authentication credentials when processing print server configuration
change requests." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running TRENDnet Print Server and is prone to
authentication bypass vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to reset
print server to factory settings or changing its IP address without password
security check and obtain the sensitive information." );
	script_tag( name: "affected", value: "TRENDnet TE100-P1U Print Server Firmware 4.11" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_vuln_check( port: port, url: "/StsSys.htm", pattern: ">TRENDNET", extra_check: ">Printer", usecache: TRUE )){
	if(http_vuln_check( port: port, url: "/Network.htm", pattern: ">TRENDNET", extra_check: make_list( "IP Address<",
		 "DNS Server Address<" ) )){
		security_message( port: port );
		exit( 0 );
	}
}

