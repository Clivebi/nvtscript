CPE = "cpe:/a:hp:power_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100457" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)" );
	script_bugtraq_id( 37866, 37867, 37873 );
	script_cve_id( "CVE-2009-3999", "CVE-2009-4000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP Power Manager Multiple Remote Code Execution Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37866" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37867" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37873" );
	script_xref( name: "URL", value: "http://h18000.www1.hp.com/products/servers/proliantstorage/power-protection/software/power-manager/index.html" );
	script_xref( name: "URL", value: "http://h18004.www1.hp.com/products/servers/proliantstorage/power-protection/software/power-manager/dl/HPPM_Windows_Readme4210_Eng.zip" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/509042" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "hp_power_manager_detect.sc" );
	script_mandatory_keys( "hp_power_manager/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "The vendor has released updates and an advisory. Please see the references
for details." );
	script_tag( name: "summary", value: "HP Power Manager is prone to multiple remote code-execution vulnerabilities
because it fails to properly bounds-check user-supplied data.

An attacker can exploit this issue to execute arbitrary code with SYSTEM privileges, resulting in a complete
compromise of the affected computer. Failed exploit attempts will result in a denial-of-service condition.

Versions prior to Power Manager 4.2.10 are affected." );
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
if(version_is_less( version: version, test_version: "4.2.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.10" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

