if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802734" );
	script_version( "2020-04-17T08:08:41+0000" );
	script_cve_id( "CVE-2011-3058", "CVE-2011-3065", "CVE-2011-3064", "CVE-2011-3063", "CVE-2011-3062", "CVE-2011-3061", "CVE-2011-3060", "CVE-2011-3059" );
	script_bugtraq_id( 52762 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-17 08:08:41 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-04-05 15:48:59 +0530 (Thu, 05 Apr 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities - April 12 (MAC OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48618/" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1026877" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/03/stable-channel-release-and-beta-channel.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 18.0.1025.142 on MAC OS X" );
	script_tag( name: "insight", value: "The flaws are due to

  - An error while handling the EUC-JP encoding system, may allow cross-site
    scripting attacks.

  - An unspecified error in Skia can be exploited to corrupt memory.

  - A use-after-free error exists in SVG clipping.

  - A validation error exists within the handling of certain navigation
    requests from the renderer.

  - An off-by-one error exists in OpenType sanitizer.

  - An error exists within SPDY proxy certificate checking.

  - An error in text fragment handling can be exploited to cause an
    out-of-bounds read.

  - An error in SVG text handling can be exploited to cause an out-of-bounds
    read." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 18.0.1025.142 or later." );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/MacOSX/Version" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "18.0.1025.142" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

