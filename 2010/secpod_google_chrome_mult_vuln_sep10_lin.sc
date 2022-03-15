if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901154" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)" );
	script_cve_id( "CVE-2010-1825", "CVE-2010-1824", "CVE-2010-1823", "CVE-2010-3417", "CVE-2010-3416", "CVE-2010-3415", "CVE-2010-3414", "CVE-2010-3413", "CVE-2010-3412", "CVE-2010-3411" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Google Chrome multiple vulnerabilities Sep-10 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41390/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/09/stable-beta-channel-updates_14.html" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to cause denial of service
  and possibly have unspecified other impact via unknown vectors." );
	script_tag( name: "affected", value: "Google Chrome version prior to 6.0.472.59 on Linux." );
	script_tag( name: "insight", value: "Multiple vulnerabilities are due to:

  - A use-after-free error exists when using document APIs during parsing.

  - A use-after-free error exists in the processing of SVG styles.

  - A use-after-free error exists in the processing of nested SVG elements.

  - An assert error exists related to cursor handling.

  - A race condition exists in the console handling.

  - An unspecified error exists in the pop-up blocking functionality.

  - An unspecified error related to Geolocation can be exploited to corrupt memory.

  - An unspecified error related to Khmer handling can be exploited to corrupt memory.

  - The application does not prompt for extension history access." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 6.0.472.59 or later." );
	script_tag( name: "summary", value: "The host is running Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "Google-Chrome/Linux/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "6.0.472.59" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "6.0.472.59" );
	security_message( port: 0, data: report );
}

