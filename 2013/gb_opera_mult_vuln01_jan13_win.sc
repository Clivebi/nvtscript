if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803138" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2012-6470", "CVE-2012-6471" );
	script_bugtraq_id( 56788, 56984 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-01-07 14:00:10 +0530 (Mon, 07 Jan 2013)" );
	script_name( "Opera Multiple Vulnerabilities-01 Jan13 (Windows)" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1038/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1040/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/unified/1212/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or spoofing the address." );
	script_tag( name: "affected", value: "Opera version before 12.12 on Windows" );
	script_tag( name: "insight", value: "- Malformed GIF images could allow execution of arbitrary code.

  - Repeated attempts to access a target site can trigger address field
    spoofing." );
	script_tag( name: "solution", value: "Upgrade to Opera version 12.12 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "12.12" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "12.12" );
	security_message( port: 0, data: report );
}

