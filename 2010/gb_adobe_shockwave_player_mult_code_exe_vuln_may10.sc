if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801335" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)" );
	script_cve_id( "CVE-2010-0127", "CVE-2010-0128", "CVE-2010-0129", "CVE-2010-0130", "CVE-2010-1280", "CVE-2010-1281", "CVE-2010-1282", "CVE-2010-1283", "CVE-2010-1284", "CVE-2010-1286", "CVE-2010-1287", "CVE-2010-1288", "CVE-2010-1289", "CVE-2010-1290", "CVE-2010-1291", "CVE-2010-1292", "CVE-2010-0987", "CVE-2010-0986" );
	script_bugtraq_id( 40083, 40076, 40082, 40084, 40081, 40078, 40077, 40088, 40091, 40085, 40089, 40096, 40094, 40087, 40090, 40079, 40093, 40086 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Shockwave Player Multiple Remote Code Execution Vulnerabilities May-10" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38751" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/codes/shockwave_mem.txt" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1128" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-12.html" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4937.php" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2010-05/0139.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_shockwave_player_detect.sc" );
	script_mandatory_keys( "Adobe/ShockwavePlayer/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code in
  the context of the affected application by tricking a user into visiting a
  specially crafted web page." );
	script_tag( name: "affected", value: "Adobe Shockwave Player prior to 11.5.7.609 on Windows." );
	script_tag( name: "insight", value: "Multiple flaws are caused by memory corruption errors, integer and buffer
  overflows, array indexing, and signedness errors when processing malformed
  'Shockwave' or 'Director' files, which could be exploited by attackers to
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page." );
	script_tag( name: "solution", value: "Upgrade to Adobe Shockwave Player 11.5.7.609." );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave Player and is prone
  to multiple remote code execution vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
shockVer = get_kb_item( "Adobe/ShockwavePlayer/Ver" );
if(!shockVer){
	exit( 0 );
}
if(version_is_less( version: shockVer, test_version: "11.5.7.609" )){
	report = report_fixed_ver( installed_version: shockVer, fixed_version: "11.5.7.609" );
	security_message( port: 0, data: report );
}

