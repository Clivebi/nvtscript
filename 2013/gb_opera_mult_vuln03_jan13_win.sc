if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803144" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2012-6461", "CVE-2012-6462", "CVE-2012-6463", "CVE-2012-6464", "CVE-2012-6465", "CVE-2012-6466", "CVE-2012-6467" );
	script_bugtraq_id( 57121, 56407, 57120, 57132 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-01-07 15:57:32 +0530 (Mon, 07 Jan 2013)" );
	script_name( "Opera Multiple Vulnerabilities-03 Jan13 (Windows)" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1034/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1035/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1033/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1032/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1031/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1030/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1029/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/unified/1210/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or disclose the information." );
	script_tag( name: "affected", value: "Opera version before 12.10 on Windows" );
	script_tag( name: "insight", value: "- Internet shortcuts used for phishing in '<img>' elements.

  - Specially crafted WebP images can be used to disclose random chunks
    of memory.

  - Specially crafted SVG images can allow execution of arbitrary code.

  - Cross domain access to object constructors can be used to facilitate
    cross-site scripting.

  - Data URIs can be used to facilitate Cross-Site Scripting.

  - CORS requests can incorrectly retrieve contents of cross origin pages.

  - Certificate revocation service failure may cause Opera to show an
    unverified site as secur." );
	script_tag( name: "solution", value: "Upgrade to Opera version 12.10 or later." );
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
if(version_is_less( version: operaVer, test_version: "12.10" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "12.10" );
	security_message( port: 0, data: report );
}

