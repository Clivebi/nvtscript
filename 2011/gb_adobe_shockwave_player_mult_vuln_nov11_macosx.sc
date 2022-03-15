if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802507" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-2446", "CVE-2011-2447", "CVE-2011-2448", "CVE-2011-2449" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-11-10 13:18:33 +0530 (Thu, 10 Nov 2011)" );
	script_name( "Adobe Shockwave Player Multiple Vulnerabilities (MAC OS X) - Nov 2011" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46667/" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-27.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Shockwave/Player/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code or
  cause a denial of service." );
	script_tag( name: "affected", value: "Adobe Shockwave Player Versions prior to 11.6.3.633 on Mac Os X" );
	script_tag( name: "insight", value: "Multiple flaws are due to an error in,

  - DIRAPI.dll and TextXtra.x32 when parsing Director file headers.

  - DIRAPI.dll when parsing rcsl chunks within Director files." );
	script_tag( name: "solution", value: "Upgrade to Adobe Shockwave Player version 11.6.3.633 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
shockVer = get_kb_item( "Adobe/Shockwave/Player/MacOSX/Version" );
if(!shockVer){
	exit( 0 );
}
if(version_is_less( version: shockVer, test_version: "11.6.3.633" )){
	report = report_fixed_ver( installed_version: shockVer, fixed_version: "11.6.3.633" );
	security_message( port: 0, data: report );
}

