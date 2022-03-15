CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805319" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2014-9450" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-01-23 10:22:50 +0530 (Fri, 23 Jan 2015)" );
	script_name( "Zabbix Multiple SQL injection Vulnerabilities - Jan15" );
	script_tag( name: "summary", value: "The host is installed with Zabbix
  and is prone to multiple SQL injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as input passed via
  the 'periods' and 'itemid' GET parameter to chart_bar.php is not properly
  sanitised before being used in an SQL query" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "Zabbix versions before 1.8.22, 2.0.x
  before 2.0.14, and 2.2.x before 2.2.8." );
	script_tag( name: "solution", value: "Upgrade to Zabbix version 1.8.22 or
  2.0.14 or 2.2.8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.zabbix.com/rn2.2.8.php" );
	script_xref( name: "URL", value: "http://www.zabbix.com/rn1.8.22.php" );
	script_xref( name: "URL", value: "http://www.zabbix.com/rn2.0.14.php" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/61554" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-8582" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "zabbix_web_detect.sc" );
	script_mandatory_keys( "Zabbix/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://www.zabbix.com" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
func check_zabbix_ver( chVer, chPort ){
	if(version_is_less( version: chVer, test_version: "1.8.22" ) || version_in_range( version: chVer, test_version: "2.0.0", test_version2: "2.0.13" ) || version_in_range( version: chVer, test_version: "2.2.0", test_version2: "2.2.7" )){
		security_message( chPort );
		exit( 0 );
	}
}
if(!zbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!zbVer = get_app_version( cpe: CPE, port: zbPort )){
	exit( 0 );
}
check_zabbix_ver( chVer: zbVer, chPort: zbPort );

