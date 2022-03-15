if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803602" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-1750" );
	script_bugtraq_id( 58539 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-14 18:45:01 +0530 (Tue, 14 May 2013)" );
	script_name( "RealNetworks RealPlayer Heap Based BoF Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://www.scip.ch/en/?vuldb.8026" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2013-1750" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/03152013_player/en" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_realplayer_detect_macosx.sc" );
	script_mandatory_keys( "RealPlayer/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to cause heap
  based buffer overflow leading to arbitrary code execution or denial of
  service condition." );
	script_tag( name: "affected", value: "RealPlayer version 12.0.0.1701 and prior on Mac OS X" );
	script_tag( name: "insight", value: "Flaw due to improper sanitization of user-supplied input when parsing MP4
  files." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer version 12.0.1.1738 or later." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to heap
  based buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/MacOSX/Version" );
if(!rpVer){
	exit( 0 );
}
if(version_is_less_equal( version: rpVer, test_version: "12.0.0.1701" )){
	report = report_fixed_ver( installed_version: rpVer, vulnerable_range: "Less than or equal to 12.0.0.1701" );
	security_message( port: 0, data: report );
	exit( 0 );
}

