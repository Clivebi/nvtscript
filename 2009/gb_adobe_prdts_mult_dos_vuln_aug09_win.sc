if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800853" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2009-08-06 06:50:55 +0200 (Thu, 06 Aug 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866", "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870" );
	script_bugtraq_id( 35900, 35904, 35906, 35901, 35905, 35902, 35907, 35908 );
	script_name( "Adobe Flash Player/Air Multiple DoS Vulnerabilities - Aug09 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35948/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2086" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb09-10.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code,
  gain elevated privileges, gain knowledge of certain information and conduct clickjacking attacks." );
	script_tag( name: "affected", value: "Adobe AIR version prior to 1.5.2

  Adobe Flash Player 9 version prior to 9.0.246.0

  Adobe Flash Player 10 version prior to 10.0.32.18 on Windows" );
	script_tag( name: "insight", value: "Multiple vulnerabilities which can be to exploited to cause memory
  corruption, null pointer, privilege escalation, heap-based buffer overflow,
  local sandbox bypass, and input validation errors when processing specially
  crafted web pages." );
	script_tag( name: "solution", value: "Update to Adobe Air 1.5.2 or Adobe Flash Player 9.0.246.0 or 10.0.32.18." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player/Air and is prone to
  multiple Denial of Service vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:flash_player",
	 "cpe:/a:adobe:adobe_air" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( cpe == "cpe:/a:adobe:flash_player" ){
	if(version_is_less( version: vers, test_version: "9.0.246.0" ) || version_in_range( version: vers, test_version: "10.0", test_version2: "10.0.32.17" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "9.0.246.0 or 10.0.32.18", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(cpe == "cpe:/a:adobe:adobe_air"){
		if(version_is_less( version: vers, test_version: "1.5.2" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "1.5.2", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

