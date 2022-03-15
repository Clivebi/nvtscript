CPE = "cpe:/a:realnetworks:realplayer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803881" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-4973", "CVE-2013-4974" );
	script_bugtraq_id( 61989, 61990 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-08-29 10:36:10 +0530 (Thu, 29 Aug 2013)" );
	script_name( "RealNetworks RealPlayer Multiple Vulnerabilities August13 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with RealPlayer and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 12.0.1.1738 or later." );
	script_tag( name: "insight", value: "Flaws are due to errors when handling filenames in RMP and when parsing
RealMedia files." );
	script_tag( name: "affected", value: "RealPlayer version prior to 12.0.1.1738 on Mac OS X." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote unauthenticated attacker to obtain
sensitive information, cause a denial of service condition, or execute
arbitrary code with the privileges of the application." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54621" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/246524" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/08232013_player/en" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_realplayer_detect_macosx.sc" );
	script_mandatory_keys( "RealPlayer/MacOSX/FullVer" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!rpVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: rpVer, test_version: "12.0.1.1738" )){
	report = report_fixed_ver( installed_version: rpVer, fixed_version: "12.0.1.1738" );
	security_message( port: 0, data: report );
	exit( 0 );
}

