if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802781" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0778" );
	script_bugtraq_id( 53419 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-05-15 13:58:42 +0530 (Tue, 15 May 2012)" );
	script_name( "Adobe Flash Professional JPG Object Processing BOF Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47116/" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027045" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-12.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_adobe_flash_professional_detect_win.sc" );
	script_mandatory_keys( "Adobe/Flash/Prof/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Flash Professional version CS5.5.1 (11.5.1.349) and prior on Windows" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'Flash.exe' when allocating memory to
  process a JPG object using its image dimensions." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Professional version CS6 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Professional and is prone
  to buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Adobe/Flash/Prof/Win/Ver" );
if(!vers){
	exit( 0 );
}
vers = eregmatch( pattern: "CS[0-9.]+ ([0-9.]+)", string: vers );
if(vers[1]){
	if(version_is_less_equal( version: vers[1], test_version: "11.5.1.349" )){
		report = report_fixed_ver( installed_version: vers[1], vulnerable_range: "Less than or equal to 11.5.1.349" );
		security_message( port: 0, data: report );
	}
}

