if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803669" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-4192", "CVE-2012-4193" );
	script_bugtraq_id( 55889 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-12 12:30:08 +0530 (Fri, 12 Jul 2013)" );
	script_name( "Mozilla Thunderbird ESR Security Bypass Vulnerabilities - Oct 12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50856" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50935" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-89.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird-ESR/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to bypass the Same Origin Policy
  and read the properties of a Location object via a crafted web site." );
	script_tag( name: "affected", value: "Thunderbird ESR versions 10.x before 10.0.9 on Windows" );
	script_tag( name: "insight", value: "Security wrappers are unwrapped without doing a security check in
  defaultValue(). This can allow for improper access to the Location object." );
	script_tag( name: "solution", value: "Upgrade to Thunderbird ESR version 10.0.9 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Thunderbird ESR and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Thunderbird-ESR/Win/Ver" );
if(vers && IsMatchRegexp( vers, "^10\\.0" )){
	if(version_in_range( version: vers, test_version: "10.0", test_version2: "10.0.8" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
exit( 99 );

