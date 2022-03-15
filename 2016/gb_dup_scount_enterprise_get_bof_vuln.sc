CPE = "cpe:/a:dboss:diskboss_enterprise";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107103" );
	script_version( "$Revision: 12313 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-06 16:11:25 +0530 (Tue, 06 Dec 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "DiskBoss Enterprise Server GET Buffer Overflow Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with DiskBoss Enterprise
  and is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of
  web requests passed via GET parameter." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote
  attackers to elevate privileges from any account type and execute code." );
	script_tag( name: "affected", value: "DiskBoss Enterprise version 7.4.28." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40869/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_diskboss_enterprise_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "Disk/Boss/Enterprise/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 8080 );
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
if(version_is_equal( version: dbossVer, test_version: "7.4.28" )){
	report = report_fixed_ver( installed_version: dbossVer, fixed_version: "None Available" );
	security_message( data: report, port: dbossPort );
	exit( 0 );
}
exit( 99 );

