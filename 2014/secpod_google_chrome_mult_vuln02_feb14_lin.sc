CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903516" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-6653", "CVE-2013-6654", "CVE-2013-6655", "CVE-2013-6656", "CVE-2013-6657", "CVE-2013-6658", "CVE-2013-6659", "CVE-2013-6660", "CVE-2013-6661" );
	script_bugtraq_id( 65699 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-02-26 11:37:10 +0530 (Wed, 26 Feb 2014)" );
	script_name( "Google Chrome Multiple Vulnerabilities-02 Feb2014 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A use-after-free error related to web contents can be exploited to cause
  memory corruption.

  - An unspecified error exists in 'SVGAnimateElement::calculateAnimatedValue'
  function related to type casting in SVG.

  - A use-after-free error related to layout can be exploited to cause memory
  corruption.

  - An error in XSS auditor 'XSSAuditor::init' function can be exploited to
  disclose certain information.

  - Another error in XSS auditor can be exploited to disclose certain information.

  - Another use-after-free error related to layout can be exploited to cause
  memory corruption

  - An unspecified error exists in 'SSLClientSocketNSS::Core::OwnAuthCertHandler'
  function related to certificates validation in TLS handshake.

  - An error in drag and drop can be exploited to disclose unspecified
  information.

  - Some unspecified errors exist. No further information is currently available." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct denial of
service, execution of arbitrary code and unspecified other impacts." );
	script_tag( name: "affected", value: "Google Chrome version prior to 33.0.1750.117 on Linux" );
	script_tag( name: "solution", value: "Upgrade to version 33.0.1750.117 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57028" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1029813" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/02/stable-channel-update_20.html" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "33.0.1750.117" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "33.0.1750.117" );
	security_message( port: 0, data: report );
	exit( 0 );
}

