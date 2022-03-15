CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808214" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-1696", "CVE-2016-1697", "CVE-2016-1698", "CVE-2016-1699", "CVE-2016-1700", "CVE-2016-1701", "CVE-2016-1702", "CVE-2016-1703" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-06-03 17:28:37 +0530 (Fri, 03 Jun 2016)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-2016-06)-Linux" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Cross-origin bypass in Extension bindings.

  - Cross-origin bypass in Blink.

  - Information leak in Extension bindings.

  - Parameter sanitization failure in DevTools.

  - Use-after-free in Extensions.

  - Use-after-free in Autofill.

  - Out-of-bounds read in Skia.

  - Various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to bypass security restrictions,
  to obtain sensitive information and to cause a denial of service
  (buffer overflow) or possibly have unspecified other impacts." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 51.0.2704.79 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  51.0.2704.79 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/06/stable-channel-update.html" );
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
if(version_is_less( version: chr_ver, test_version: "51.0.2704.79" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "51.0.2704.79" );
	security_message( data: report );
	exit( 0 );
}

