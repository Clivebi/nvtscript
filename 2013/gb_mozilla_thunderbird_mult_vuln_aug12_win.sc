if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803905" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-3974", "CVE-2012-3980" );
	script_bugtraq_id( 55249 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-17 12:16:46 +0530 (Wed, 17 Jul 2013)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities - August12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50088" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027450" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027451" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-67.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-72.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 15.0 on Windows" );
	script_tag( name: "insight", value: "- An error in the installer will launch incorrect executable following new
    installation via a crafted executable file in a root directory.

  - An error in the web console can be exploited to inject arbitrary code that
    will be executed with chrome privileges." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 15.0 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Thunderbird and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "15.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "15.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

