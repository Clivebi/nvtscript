if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900854" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-7197" );
	script_name( "G15Daemon Unspecified Vulnerability" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/apps/freshmeat/2008-01/0019.html" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_g15daemon_detect.sc" );
	script_mandatory_keys( "G15Daemon/Ver" );
	script_tag( name: "impact", value: "Unknown impact." );
	script_tag( name: "affected", value: "G15Daemon version prior to 1.9.4" );
	script_tag( name: "insight", value: "Multiple unspecified vulnerabilities exist, details are not available." );
	script_tag( name: "solution", value: "Upgrade to version 1.9.4 or later." );
	script_tag( name: "summary", value: "This host has G15Daemon installed and is prone to Unspecified
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
g15dVer = get_kb_item( "G15Daemon/Ver" );
if(!g15dVer){
	exit( 0 );
}
if(version_is_less( version: g15dVer, test_version: "1.9.4" )){
	report = report_fixed_ver( installed_version: g15dVer, fixed_version: "1.9.4" );
	security_message( port: 0, data: report );
}

