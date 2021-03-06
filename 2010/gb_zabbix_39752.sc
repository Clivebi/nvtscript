CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100621" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)" );
	script_cve_id( "CVE-2010-5049" );
	script_bugtraq_id( 39752 );
	script_name( "ZABBIX 'nav_time' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39752" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "zabbix_web_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Zabbix/installed" );
	script_tag( name: "summary", value: "ZABBIX is prone to an SQL-injection vulnerability because it fails
to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database." );
	script_tag( name: "affected", value: "ZABBIX versions 1.8.1 and prior are vulnerable." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
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
if(version_is_less_equal( version: vers, test_version: "1.8.1" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

