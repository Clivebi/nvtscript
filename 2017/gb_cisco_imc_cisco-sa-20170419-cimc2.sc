CPE = "cpe:/a:cisco:integrated_management_controller";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106773" );
	script_cve_id( "CVE-2017-6617" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_name( "Cisco Integrated Management Controller User Session Hijacking Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-cimc2" );
	script_tag( name: "summary", value: "A vulnerability in the session identification management functionality of
the web-based GUI of Cisco Integrated Management Controller (IMC) could allow an unauthenticated, remote attacker
to hijack a valid user session on an affected system." );
	script_tag( name: "insight", value: "The vulnerability exists because the affected software does not assign a
new session identifier to a user session when a user authenticates to the web-based GUI. An attacker could exploit
this vulnerability by using a hijacked session identifier to connect to the software through the web-based GUI." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to hijack an authenticated
user's browser session on the affected system." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 3.0.1d or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:28:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-20 14:59:32 +0200 (Thu, 20 Apr 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_imc_detect.sc" );
	script_mandatory_keys( "cisco_imc/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
version = str_replace( string: version, find: ")", replace: "" );
version = str_replace( string: version, find: "(", replace: "." );
if(version == "3.0.1c"){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.1d" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

