CPE = "cpe:/a:dup:dup_scout_enterprise";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809487" );
	script_version( "$Revision: 12455 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-02 12:30:49 +0530 (Fri, 02 Dec 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dup Scout Enterprise Server 'Login' Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "The host is running Dup Scout Enterprise
  Server and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of
  web request passed via an overly long string to 'Login' page." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition." );
	script_tag( name: "affected", value: "Dup Scout Enterprise version 9.1.14 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.dupscout.com" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40832/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_dup_scount_enterprise_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "Dup/Scout/Enterprise/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!dupPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dupVer = get_app_version( cpe: CPE, port: dupPort )){
	exit( 0 );
}
if(version_is_less_equal( version: dupVer, test_version: "9.1.14" )){
	report = report_fixed_ver( installed_version: dupVer, fixed_version: "None Available" );
	security_message( data: report, port: dupPort );
	exit( 0 );
}

