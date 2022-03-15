if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802300" );
	script_version( "2020-11-12T08:48:24+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 08:48:24 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)" );
	script_cve_id( "CVE-2011-1924" );
	script_bugtraq_id( 46618 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Tor Directory Authority 'policy_summarize' Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43548" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_tor_detect_win.sc" );
	script_mandatory_keys( "Tor/Win/Ver" );
	script_tag( name: "affected", value: "Tor version prior to 0.2.1.30 on Windows." );
	script_tag( name: "insight", value: "The flaw is caused by a boundary error within the policy_summarize function
  in Tor, which can be exploited to crash a Tor directory authority." );
	script_tag( name: "solution", value: "Upgrade to Tor version 0.2.1.30 or later." );
	script_tag( name: "summary", value: "This host is installed with Tor and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the user running the application. Failed exploit
  attempts will likely result in denial-of-service conditions." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
torVer = get_kb_item( "Tor/Win/Ver" );
if(!torVer){
	exit( 0 );
}
torVer = ereg_replace( pattern: "-", replace: ".", string: torVer );
if(version_is_less( version: torVer, test_version: "0.2.1.30" )){
	report = report_fixed_ver( installed_version: torVer, fixed_version: "0.2.1.30" );
	security_message( port: 0, data: report );
}

