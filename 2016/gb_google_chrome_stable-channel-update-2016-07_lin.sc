CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808264" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-1706", "CVE-2016-1707", "CVE-2016-1708", "CVE-2016-1709", "CVE-2016-1710", "CVE-2016-1711", "CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5131", "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135", "CVE-2016-5136", "CVE-2016-5137", "CVE-2016-1705" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-07-22 13:12:56 +0530 (Fri, 22 Jul 2016)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-2016-07)-Linux" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Sandbox escape in PPAPI

  - URL spoofing on iOS

  - Use-after-free in Extensions

  - Heap-buffer-overflow in sfntly

  - Same-origin bypass in Blink

  - Use-after-free in Blink

  - Same-origin bypass in V8

  - Memory corruption in V8

  - URL spoofing

  - Use-after-free in libxml

  - Limited same-origin bypass in Service Workers

  - Origin confusion in proxy authentication

  - URL leakage via PAC script

  - Content-Security-Policy bypass

  - Use after free in extensions

  - History sniffing with HSTS and CSP" );
	script_tag( name: "impact", value: "Successful exploitation of these vulnerabilities
  will allow remote attackers to bypass security, to cause denial of service and
  some unspecified impacts." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 52.0.2743.82 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  52.0.2743.82 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/07/stable-channel-update.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "52.0.2743.82" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "52.0.2743.82" );
	security_message( data: report );
	exit( 0 );
}

