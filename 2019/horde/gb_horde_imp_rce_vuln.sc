CPE = "cpe:/a:horde:imp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141879" );
	script_version( "2020-01-20T08:55:19+0000" );
	script_tag( name: "last_modification", value: "2020-01-20 08:55:19 +0000 (Mon, 20 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-01-15 16:36:52 +0700 (Tue, 15 Jan 2019)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Horde IMP <= 7.0.0 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "imp_detect.sc" );
	script_mandatory_keys( "horde/imp/detected" );
	script_tag( name: "summary", value: "Horde IMP is prone to an unauthenticated remote code execution
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An unauthenticated attacker may execute arbitrary commands." );
	script_tag( name: "affected", value: "Horde IMP 6.2.22 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/46136" );
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
if(version_is_less_equal( version: version, test_version: "7.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

