CPE = "cpe:/a:solarwinds:ip_address_manager_web_interface";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105969" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-06 13:50:43 +0700 (Fri, 06 Mar 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-9566" );
	script_name( "SolarWinds IP Address Manager Multiple SQL Injection Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_orion_ipam_detect.sc" );
	script_mandatory_keys( "orion_ipam/installed" );
	script_tag( name: "summary", value: "SolarWinds IP Address Manager is prone to multiple
SQL Injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "On both the GetAccounts and GetAccountGroups endpoints, the
'sort' and 'dir' parameters are susceptible to boolean-/time-based, and stacked injections. The attacker
has to be authenticated but it can be even exploited under a guest account." );
	script_tag( name: "impact", value: "An authenticated attacker might execute arbitrary SQL commands
to compromise the application, access or modify data, or exploit latent vulnerabilities in the
underlying database." );
	script_tag( name: "affected", value: "SolarWinds IPAM 4.2 and previous." );
	script_tag( name: "solution", value: "Upgrade to SolarWinds IPAM 4.3 or later." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Mar/18" );
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
if(version_is_less( version: version, test_version: "4.3" )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     4.3\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

