CPE = "cpe:/a:diskpulse:diskpulse_enterprise_web_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811717" );
	script_version( "$Revision: 11923 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-16 12:38:56 +0200 (Tue, 16 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-08-30 17:59:00 +0530 (Wed, 30 Aug 2017)" );
	script_name( "Disk Pulse Enterprise Server Buffer Overflow Vulnerability - Aug17" );
	script_tag( name: "summary", value: "The host is running Disk Pulse Enterprise
  Server and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to server." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition." );
	script_tag( name: "affected", value: "Disk Pulse Enterprise version 10.0.12 and prior." );
	script_tag( name: "solution", value: "Update Disk Pulse Enterprise to version 10.2 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42560" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_disk_pulse_enterprise_server_detect.sc" );
	script_mandatory_keys( "DiskPulse/Enterprise/Server/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!diskPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!diskVer = get_app_version( cpe: CPE, port: diskPort )){
	exit( 0 );
}
if(version_is_less_equal( version: diskVer, test_version: "10.0.12" )){
	report = report_fixed_ver( installed_version: diskVer, fixed_version: "10.2" );
	security_message( port: diskPort, data: report );
	exit( 0 );
}
exit( 0 );

