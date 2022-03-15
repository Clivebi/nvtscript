CPE = "cpe:/a:advantech:advantech_webaccess";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106108" );
	script_version( "2019-04-06T12:52:40+0000" );
	script_tag( name: "last_modification", value: "2019-04-06 12:52:40 +0000 (Sat, 06 Apr 2019)" );
	script_tag( name: "creation_date", value: "2016-06-24 11:38:08 +0700 (Fri, 24 Jun 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2016-4525", "CVE-2016-4528", "CVE-2016-5810" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Advantech WebAccess Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_advantech_webaccess_consolidation.sc" );
	script_mandatory_keys( "advantech/webaccess/detected" );
	script_tag( name: "summary", value: "Advantech WebAccess is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Advantech WebAccess is prone to multiple vulnerabilities:

Several ActiveX controls are intended for restricted use, but have been marked as safe-for-scripting.
(CVE-2016-4525)

A specially crafted DLL file can cause a buffer overflow. (CVE-2016-4528)

A properly authenticated administrator can view passwords for other administrators. (CVE-2016-5810)" );
	script_tag( name: "impact", value: "A local attacker may insert and run arbitrary code on an affected
system. A authenticated administrator may view passwords from other administrators." );
	script_tag( name: "affected", value: "WebAccess versions prior to 8.1_20160519" );
	script_tag( name: "solution", value: "Upgrade to Version 8.1_20160519 or later" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-16-173-01" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port )){
	exit( 0 );
}
path = infos["location"];
vers = infos["version"];
if(version_is_less( version: vers, test_version: "8.1.2016.05.19" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.1.2016.05.19", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

