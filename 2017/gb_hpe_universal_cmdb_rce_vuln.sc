CPE = "cpe:/a:hp:universal_cmbd_foundation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106868" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-13 14:33:13 +0700 (Tue, 13 Jun 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-15 15:14:00 +0000 (Thu, 15 Mar 2018)" );
	script_cve_id( "CVE-2017-8947" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HPE Universal CMDB Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hpe_universal_cmdb_detect.sc" );
	script_mandatory_keys( "HP/UCMDB/Installed" );
	script_tag( name: "summary", value: "A potential security vulnerability has been identified in HPE UCMDB. The
vulnerability could be remotely exploited to allow execution of code." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "HP UCMDB Configuration Manager Software version 10.10, 10.11, 10.20, 10.21,
10.22, 10.30 and 10.31." );
	script_tag( name: "solution", value: "See the advisory for a solution." );
	script_xref( name: "URL", value: "https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03758en_us" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version == "10.10" || version == "10.11" || version == "10.20" || version == "10.21" || version == "10.22" || version == "10.30" || version == "10.31"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

