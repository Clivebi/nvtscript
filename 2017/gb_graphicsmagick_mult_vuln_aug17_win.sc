CPE = "cpe:/a:graphicsmagick:graphicsmagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112027" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-11642", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065", "CVE-2017-13066", "CVE-2017-13147", "CVE-2017-13148" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-18 15:05:00 +0000 (Mon, 18 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-08-23 11:38:13 +0200 (Wed, 23 Aug 2017)" );
	script_name( "GraphicsMagick Multiple Vulnerabilities - Aug17 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with GraphicsMagick
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "GraphicsMagick 1.3.26 and prior is prone to multiple vulnerabilities:

  - Allocation failure vulnerabilities.

  - Heap buffer overflow vulnerabilities.

  - Null pointer dereference vulnerabilities.

  - Memory leak vulnerabilities.

  - Invalid memory read vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a denial of service via a crafted file." );
	script_tag( name: "affected", value: "GraphicsMagick version 1.3.26 and earlier on Windows" );
	script_tag( name: "solution", value: "Updates are available, see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/bugs/434/" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/bugs/436/" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/bugs/435/" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/bugs/430/" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/bugs/446/" );
	script_xref( name: "URL", value: "https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-invalid-memory-read-in-setimagecolorcallback-image-c/" );
	script_xref( name: "URL", value: "https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-use-after-free-in-readwmfimage-wmf-c/" );
	script_xref( name: "URL", value: "https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-heap-based-buffer-overflow-in-readsunimage-sun-c/" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_graphicsmagick_detect_win.sc" );
	script_mandatory_keys( "GraphicsMagick/Win/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!gmVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: gmVer, test_version: "1.3.26" )){
	report = report_fixed_ver( installed_version: gmVer, fixed_version: "See Vendor" );
	security_message( data: report );
	exit( 0 );
}

