CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100406" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)" );
	script_cve_id( "CVE-2009-4499", "CVE-2009-4501" );
	script_bugtraq_id( 37309 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "ZABBIX Denial Of Service and SQL Injection Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "zabbix_detect.sc", "zabbix_web_detect.sc" );
	script_mandatory_keys( "Zabbix/Web/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37740/" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-1031" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-1355" );
	script_tag( name: "summary", value: "ZABBIX is prone to a denial-of-service vulnerability and an SQL-
  injection vulnerability." );
	script_tag( name: "impact", value: "Successful exploits may allow remote attackers to crash the affected
  application, exploit latent vulnerabilities in the underlying database, access or modify data, or
  compromise the application." );
	script_tag( name: "affected", value: "Versions prior to ZABBIX 1.6.8 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.6.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.6.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

