if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802651" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-3562", "CVE-2012-3563", "CVE-2012-3564", "CVE-2012-3565", "CVE-2012-3566", "CVE-2012-3567", "CVE-2012-3568" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 15:15:15 +0530 (Thu, 21 Jun 2012)" );
	script_name( "Opera Multiple Denial of Service Vulnerabilities - June12 (Linux)" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/windows/1200b/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_opera_detection_linux_900037.sc" );
	script_mandatory_keys( "Opera/Linux/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker crash the browser leading to
  denial of service." );
	script_tag( name: "affected", value: "Opera version prior to 12.00 Beta on Linux" );
	script_tag( name: "insight", value: "- A denial of service via crafted characters in domain names.

  - A denial of service (application crash) via crafted WebGL content.

  - A denial of service (memory consumption or application hang) via an
    IFRAME element that uses the src='#' syntax to embed a parent document.

  - A denial of service (application hang) via JavaScript code that changes
    a form before submission.

  - A denial of service (application hang) via an absolutely positioned
    wrap=off TEXTAREA element located next to an 'overflow: auto' block
    element.

  - A denial of service (application crash) via a web page that contains
    invalid character encodings.

  - A denial of service (application crash) via a crafted web page that is
    not properly handled during a reload." );
	script_tag( name: "solution", value: "Upgrade to Opera version 12.00 Beta or later." );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to multiple
  denial of service vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Linux/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less_equal( version: operaVer, test_version: "11.65" )){
	report = report_fixed_ver( installed_version: operaVer, vulnerable_range: "Less than or equal to 11.65" );
	security_message( port: 0, data: report );
}

