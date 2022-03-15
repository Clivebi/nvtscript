CPE = "cpe:/a:flexense:syncbreeze";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809481" );
	script_version( "$Revision: 12813 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-18 08:43:29 +0100 (Tue, 18 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-29 12:58:33 +0530 (Tue, 29 Nov 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Sync Breeze Enterprise Server Buffer Overflow Vulnerability - Nov16" );
	script_tag( name: "summary", value: "The host is running Sync Breeze Enterprise
  Server and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to 'Login' request." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition." );
	script_tag( name: "affected", value: "Sync Breeze Enterprise version 9.1.16
  and earlier." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.syncbreeze.com" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40831" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_sync_breeze_enterprise_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "flexsense_syncbreeze/detected", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!syncPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!syncVer = get_app_version( cpe: CPE, port: syncPort )){
	exit( 0 );
}
if(version_is_less_equal( version: syncVer, test_version: "9.1.16" )){
	report = report_fixed_ver( installed_version: syncVer, fixed_version: "None Available" );
	security_message( data: report, port: syncPort );
	exit( 0 );
}

