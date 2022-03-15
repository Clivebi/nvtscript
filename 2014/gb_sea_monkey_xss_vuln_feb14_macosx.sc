CPE = "cpe:/a:mozilla:seamonkey";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804508" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-6674", "CVE-2014-2018" );
	script_bugtraq_id( 65158, 65620 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-02-19 18:12:17 +0530 (Wed, 19 Feb 2014)" );
	script_name( "SeaMonkey Multiple XSS Vulnerabilities Feb14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with SeaMonkey and is prone to multiple cross site
scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to the program does not validate input related to data URLs in
IFRAME elements or EMBED or OBJECT element before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary script code
in a user's browser session within the trust relationship between their
browser and the server." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.20 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to SeaMonkey version 2.20 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/863369" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/31223" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-14.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "SeaMonkey/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!smVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: smVer, test_version: "2.20" )){
	report = report_fixed_ver( installed_version: smVer, fixed_version: "2.20" );
	security_message( port: 0, data: report );
	exit( 0 );
}

