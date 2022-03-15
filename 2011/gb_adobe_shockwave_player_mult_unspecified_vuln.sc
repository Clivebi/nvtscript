if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802301" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-06-21 13:52:36 +0200 (Tue, 21 Jun 2011)" );
	script_cve_id( "CVE-2011-0317", "CVE-2011-0318", "CVE-2011-0319", "CVE-2011-0320", "CVE-2011-0335", "CVE-2011-2108", "CVE-2011-2109", "CVE-2011-2111", "CVE-2011-2112", "CVE-2011-2113", "CVE-2011-2114", "CVE-2011-2115", "CVE-2011-2118", "CVE-2011-2119", "CVE-2011-2120", "CVE-2011-2121", "CVE-2011-2122", "CVE-2011-2123", "CVE-2011-2124", "CVE-2011-2125", "CVE-2011-2126", "CVE-2011-2127", "CVE-2011-2128" );
	script_bugtraq_id( 48284, 48286, 48287, 48288, 48275, 48311, 48273, 48300, 48278, 48306, 48298, 48299, 48304, 48296, 48307, 48302, 48297, 48310, 48294, 48308, 48309, 48289, 48290 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Shockwave Player Multiple Unspecified Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-17.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_shockwave_player_detect.sc" );
	script_mandatory_keys( "Adobe/ShockwavePlayer/Ver" );
	script_tag( name: "impact", value: "Successful attack could allow attackers to execute of arbitrary code or
  cause a denial of service." );
	script_tag( name: "affected", value: "Adobe Shockwave Player version before 11.6.0.626 on Windows." );
	script_tag( name: "insight", value: "The flaws are due to unspecified vectors. Please see the references
  for more details." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 11.6.0.626 or later." );
	script_tag( name: "summary", value: "This host has Adobe Shockwave Player installed and is prone to
  multiple unspecified vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
shockVer = get_kb_item( "Adobe/ShockwavePlayer/Ver" );
if(!shockVer){
	exit( 0 );
}
if(version_is_less( version: shockVer, test_version: "11.6.0.626" )){
	report = report_fixed_ver( installed_version: shockVer, fixed_version: "11.6.0.626" );
	security_message( port: 0, data: report );
}

