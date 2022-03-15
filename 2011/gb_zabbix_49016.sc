CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103213" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-19 14:58:19 +0200 (Fri, 19 Aug 2011)" );
	script_bugtraq_id( 49016 );
	script_cve_id( "CVE-2011-2904" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ZABBIX 'backurl' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49016" );
	script_xref( name: "URL", value: "http://www.zabbix.com/rn1.8.6.php" );
	script_xref( name: "URL", value: "http://www.zabbix.org" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-3835" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "zabbix_detect.sc", "zabbix_web_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Zabbix/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "ZABBIX is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Version prior to ZABBIX 1.8.6 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_is_less( version: vers, test_version: "1.8.6" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "1.8.6" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

