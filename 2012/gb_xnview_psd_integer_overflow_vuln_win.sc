if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802443" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-0684", "CVE-2012-0685" );
	script_bugtraq_id( 51546 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-07-24 14:02:14 +0530 (Tue, 24 Jul 2012)" );
	script_name( "XnView PSD Record Type Parsing Integer Overflow Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_xnview_detect_win.sc" );
	script_mandatory_keys( "XnView/Win/Ver" );
	script_tag( name: "summary", value: "This host has XnView installed and is prone to multiple integer
  overflow vulnerabilities." );
	script_tag( name: "insight", value: "The flaws are due to integer overflow errors within the parsing of PSD
  record types and can be exploited to cause buffer overflows via a specially
  crafted PSD image." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code on the
  system or cause a denial of service condition." );
	script_tag( name: "affected", value: "XnView versions 1.98.2 and prior on windows" );
	script_tag( name: "solution", value: "Update to XnView version 1.98.5 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/VulnerabilityResearchAdvisories/2012/msvr12-001" );
	exit( 0 );
}
require("version_func.inc.sc");
xnviewVer = get_kb_item( "XnView/Win/Ver" );
if(isnull( xnviewVer )){
	exit( 0 );
}
if(version_is_less_equal( version: xnviewVer, test_version: "1.98.2" )){
	report = report_fixed_ver( installed_version: xnviewVer, vulnerable_range: "Less than or equal to 1.98.2" );
	security_message( port: 0, data: report );
}
exit( 99 );

