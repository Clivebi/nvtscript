CPE = "cpe:/a:dboss:diskboss_enterprise";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107125" );
	script_version( "$Revision: 12467 $" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-21 15:04:59 +0100 (Wed, 21 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2017-01-17 16:11:25 +0530 (Tue, 17 Jan 2017)" );
	script_name( "DiskBoss Enterprise Server POST Buffer Overflow (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_diskboss_enterprise_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "Disk/Boss/Enterprise/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 8080 );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/41003/" );
	script_xref( name: "URL", value: "https://vuldb.com/de/?id.95194" );
	script_tag( name: "summary", value: "The host is installed with DiskBoss Enterprise
  and is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of
  web requests passed via POST request." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote
  attackers to elevate privileges from any account type and execute code." );
	script_tag( name: "affected", value: "DiskBoss Enterprise v7.5.12" );
	script_tag( name: "solution", value: "Update to version 9.0 or above." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!dbossPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dbossVer = get_app_version( cpe: CPE, port: dbossPort )){
	exit( 0 );
}
if(version_in_range( version: dbossVer, test_version: "7.0.0", test_version2: "7.5.12" )){
	report = report_fixed_ver( installed_version: dbossVer, fixed_version: "9.0" );
	security_message( data: report, port: dbossPort );
	exit( 0 );
}
exit( 99 );

