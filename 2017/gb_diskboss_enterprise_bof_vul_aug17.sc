CPE = "cpe:/a:dboss:diskboss_enterprise";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107185" );
	script_version( "$Revision: 12467 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-21 15:04:59 +0100 (Wed, 21 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2017-10-06 16:11:25 +0530 (Fri, 06 Oct 2017)" );
	script_name( "DiskBoss Enterprise Server 8.3.12 Buffer Overflow Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_diskboss_enterprise_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "Disk/Boss/Enterprise/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 8080 );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/143941/DiskBoss-Enterprise-8.3.12-Buffer-Overflow.html" );
	script_tag( name: "summary", value: "The host is installed with DiskBoss Enterprise
  and is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote
  attackers to elevate privileges from any account type and execute code." );
	script_tag( name: "affected", value: "DiskBoss Enterprise v8.3.12" );
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
if(version_in_range( version: dbossVer, test_version: "8.0.0", test_version2: "8.3.12" )){
	report = report_fixed_ver( installed_version: dbossVer, fixed_version: "9.0" );
	security_message( data: report, port: dbossPort );
	exit( 0 );
}
exit( 99 );

