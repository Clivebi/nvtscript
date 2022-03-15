if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801679" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)" );
	script_bugtraq_id( 45170 );
	script_cve_id( "CVE-2010-4482", "CVE-2010-4483", "CVE-2010-4484", "CVE-2010-4485", "CVE-2010-4486", "CVE-2010-4487", "CVE-2010-4488", "CVE-2010-4489", "CVE-2010-4490", "CVE-2010-4491", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4494" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Google Chrome multiple vulnerabilities - Dec10 (Linux)" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/12/stable-beta-channel-updates.html" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to cause a denial of
  service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 8.0.552.215 on Linux." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Possible pop-up blocker bypass via unknown vectors.

  - Cross-origin video theft with canvas elements allows remote attackers to
    bypass the Same Origin Policy and obtain potentially sensitive video data.

  - Improper handling of HTML5 databases allows attackers to cause a denial of
    service.

  - Excessive file dialogs could lead to a browser crash.

  - Use after free error in history handling.

  - Incomplete blacklist vulnerability allows remote attackers to have an
    unspecified impact via a 'dangerous file'.

  - Browser crash with HTTP proxy authentication.

  - Out-of-bounds read regression in WebM video support.

  - Crash due to bad indexing with malformed video.

  - Possible browser memory corruption via malicious privileged extension.

  - Use after free error with SVG animations.

  - Use after free in mouse dragging event handling.

  - A double free error in XPath handling." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 8.0.552.215 or later." );
	script_tag( name: "summary", value: "The host is running Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "Google-Chrome/Linux/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "8.0.552.215" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "8.0.552.215" );
	security_message( port: 0, data: report );
}

