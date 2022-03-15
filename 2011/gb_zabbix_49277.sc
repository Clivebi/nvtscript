CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103260" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-09-20 13:31:33 +0200 (Tue, 20 Sep 2011)" );
	script_bugtraq_id( 49277 );
	script_cve_id( "CVE-2011-3265" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "ZABBIX 'popup.php' Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49277" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-3955" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "zabbix_detect.sc", "zabbix_web_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Zabbix/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the reference for more details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "ZABBIX is prone to an information-disclosure vulnerability because it
fails to sufficiently validate user-supplied data." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to read the contents of arbitrary
database tables. This may allow the attacker to obtain sensitive
information. Other attacks are also possible." );
	script_tag( name: "affected", value: "Version prior to ZABBIX 1.8.7 are vulnerable." );
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
if(version_is_less( version: vers, test_version: "1.8.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.8.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

