CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103348" );
	script_bugtraq_id( 50803 );
	script_cve_id( "CVE-2011-4674" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_name( "ZABBIX 'only_hostid' Parameter SQL Injection Vulnerability" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-11-30 11:34:16 +0100 (Wed, 30 Nov 2011)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "zabbix_detect.sc", "zabbix_web_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Zabbix/Web/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50803" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-4385" );
	script_tag( name: "summary", value: "ZABBIX is prone to an SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in an
  SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database." );
	script_tag( name: "affected", value: "ZABBIX versions 1.8.3 and 1.8.4 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_is_equal( version: vers, test_version: "1.8.3" ) || version_is_equal( version: vers, test_version: "1.8.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

