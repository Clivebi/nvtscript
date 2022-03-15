CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902413" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)" );
	script_cve_id( "CVE-2011-1540", "CVE-2011-1541" );
	script_bugtraq_id( 47507, 47512 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "HP System Management Homepage Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_tag( name: "insight", value: "The flaw is caused by unspecified errors with unknown attack vectors." );
	script_tag( name: "solution", value: "Apply patch or update to HP SMH version 6.3 or later." );
	script_tag( name: "summary", value: "This host is running  HP System Management Homepage (SMH) and is
  prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  on the target system and also cause Denial of Service (DoS)." );
	script_tag( name: "affected", value: "HP System Management Homepage (SMH) prior to 6.3." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_is_less( version: version, test_version: "6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

