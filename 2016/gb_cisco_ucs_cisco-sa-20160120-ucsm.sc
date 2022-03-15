CPE = "cpe:/a:cisco:unified_computing_system_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105526" );
	script_cve_id( "CVE-2015-6435" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-03-06T09:16:18+0000" );
	script_name( "Cisco Unified Computing System Manager Remote Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160120-ucsm" );
	script_tag( name: "last_modification", value: "2020-03-06 09:16:18 +0000 (Fri, 06 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-01-25 15:34:07 +0100 (Mon, 25 Jan 2016)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ucs_manager_detect.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "cisco_ucs_manager/installed" );
	script_tag( name: "impact", value: "An exploit could allow the attacker to execute arbitrary commands on the Cisco UCS Manager or the Cisco Firepower 9000 Series appliance." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to unprotected calling of shell commands in the CGI script. An attacker could exploit this vulnerability by sending a crafted HTTP request to the Cisco UCS Manager appliance." );
	script_tag( name: "solution", value: "Updates are available" );
	script_tag( name: "summary", value: "A vulnerability in a CGI script in the Cisco Unified Computing System (UCS) Manager and the Cisco Firepower 9000 Series appliance could allow an unauthenticated, remote attacker to execute arbitrary commands on the Cisco UCS Manager or the Cisco Firepower 9000 Series appliance." );
	script_tag( name: "affected", value: "The first fixed releases of Cisco UCS Manager are 2.2(4b), 2.2(5a), and 3.0(2e). Earlier versions of 2.2.x are affected by this vulnerability." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
rep_version = version;
vers = eregmatch( pattern: "^([0-9.]+)\\(([^)]+)\\)", string: version );
if(isnull( vers[1] ) || isnull( vers[2] )){
	exit( 0 );
}
major = vers[1];
build = vers[2];
if(version_is_less( version: major, test_version: "2.2" )){
	exit( 99 );
}
if(IsMatchRegexp( major, "^2\\.2" )){
	if(IsMatchRegexp( build, "^([1-3]+)" )){
		fix = "2.2(4b)";
	}
	if(IsMatchRegexp( build, "^(4($|a))" )){
		fix = "2.2(4b)";
	}
	if(IsMatchRegexp( build, "^(5($))" )){
		fix = "2.2(5a)";
	}
	if(IsMatchRegexp( build, "^(6($))" )){
		fix = "2.2(6a)";
	}
}
if(IsMatchRegexp( major, "^3\\.0" )){
	if(IsMatchRegexp( build, "^[01]+" )){
		fix = "3.0(2e)";
	}
	if(IsMatchRegexp( build, "^2[a-d]+" )){
		fix = "3.0(2e)";
	}
}
if(IsMatchRegexp( major, "^3\\.1" )){
	if(IsMatchRegexp( build, "^($|[a-d]+)" )){
		fix = "3.1(e)";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: rep_version, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

