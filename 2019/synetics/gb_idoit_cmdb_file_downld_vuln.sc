CPE = "cpe:/a:synetics:i-doit";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141877" );
	script_version( "2020-01-20T08:55:19+0000" );
	script_tag( name: "last_modification", value: "2020-01-20 08:55:19 +0000 (Mon, 20 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-01-15 14:16:19 +0700 (Tue, 15 Jan 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "i-doit CMDB <= 1.12 Arbitrary File Download Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_idoit_cmdb_detect.sc" );
	script_mandatory_keys( "idoit_cmdb/detected" );
	script_tag( name: "summary", value: "i-doit CMDB is prone to an authenticated arbitrary file download
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An authenticated attacker may download arbitrary files." );
	script_tag( name: "affected", value: "i-doit CMDB 1.12 and prior." );
	script_tag( name: "solution", value: "Update to i-doit CMDB 1.12.1 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/46133" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/46134" );
	script_xref( name: "URL", value: "https://sourceforge.net/projects/i-doit/files/i-doit/1.12.1/CHANGELOG/download" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.12.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.12.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

