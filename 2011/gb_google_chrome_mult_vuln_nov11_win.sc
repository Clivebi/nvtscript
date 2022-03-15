if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802345" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2011-3892", "CVE-2011-3893", "CVE-2011-3894", "CVE-2011-3895", "CVE-2011-3896", "CVE-2011-3897", "CVE-2011-3898" );
	script_bugtraq_id( 50642 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-11-14 11:11:11 +0530 (Mon, 14 Nov 2011)" );
	script_name( "Google Chrome Multiple Vulnerabilities - November11 (Windows)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026313" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/11/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service, and disclose potentially sensitive information,
  other attacks may also be possible." );
	script_tag( name: "affected", value: "Google Chrome version prior to 15.0.874.120 on Windows" );
	script_tag( name: "insight", value: "Multiple vulnerabilities are due to:

  - A double free error in the Theora decoder exists when handling a crafted
    stream.

  - An error in implementing the MKV and Vorbis media handlers.

  - A memory corruption regression error in VP8 decoding when handling a
    crafted stream.

  - Heap overflow in the Vorbis decoder when handling a crafted stream.

  - Buffer overflow error in the shader variable mapping.

  - A use-after-free error exists related to editing.

  - Fails to ask permission to run applets in Java Runtime Environment (JRE) 7." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 15.0.874.120 or later." );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "15.0.874.120" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "15.0.874.120" );
	security_message( port: 0, data: report );
}

