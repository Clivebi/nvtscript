if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71529" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2815", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2819", "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2822", "CVE-2012-2823", "CVE-2012-2824", "CVE-2012-2826", "CVE-2012-2827", "CVE-2012-2828", "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831", "CVE-2012-2832", "CVE-2012-2833", "CVE-2012-2834" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)" );
	script_name( "FreeBSD Ports: chromium" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: chromium

CVE-2012-2815
Google Chrome before 20.0.1132.43 allows remote attackers to obtain
potentially sensitive information from a fragment identifier by
leveraging access to an IFRAME element associated with a different
domain.
CVE-2012-2817
Use-after-free vulnerability in Google Chrome before 20.0.1132.43
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to tables that have
sections.
CVE-2012-2818
Use-after-free vulnerability in Google Chrome before 20.0.1132.43
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the layout of
documents that use the Cascading Style Sheets (CSS) counters feature.
CVE-2012-2819
The texSubImage2D implementation in the WebGL subsystem in Google
Chrome before 20.0.1132.43 does not properly handle uploads to
floating-point textures, which allows remote attackers to cause a
denial of service (assertion failure and application crash) or
possibly have unspecified other impact via a crafted web page, as
demonstrated by certain WebGL performance tests, aka rdar problem
11520387.
CVE-2012-2820
Google Chrome before 20.0.1132.43 does not properly implement SVG
filters, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2012-2821
The autofill implementation in Google Chrome before 20.0.1132.43 does
not properly display text, which has unspecified impact and remote
attack vectors.
CVE-2012-2822
The PDF functionality in Google Chrome before 20.0.1132.43 allows
remote attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.

Text truncated. Please see the references for more information." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/search/label/Stable%20updates" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/ff922811-c096-11e1-b0f4-00262d5ed8ee.html" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "chromium" );
if(!isnull( bver ) && revcomp( a: bver, b: "20.0.1132.43" ) < 0){
	txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

