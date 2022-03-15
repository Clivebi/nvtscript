if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71288" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3057", "CVE-2011-3058", "CVE-2011-3059", "CVE-2011-3060", "CVE-2011-3061", "CVE-2011-3062", "CVE-2011-3063", "CVE-2011-3064", "CVE-2011-3065" );
	script_version( "2020-06-03T08:38:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)" );
	script_name( "FreeBSD Ports: chromium" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: chromium

CVE-2011-3057
Google V8, as used in Google Chrome before 17.0.963.83, allows remote
attackers to cause a denial of service via vectors that trigger an
invalid read operation.
CVE-2011-3058
Google Chrome before 18.0.1025.142 does not properly handle the EUC-JP
encoding system, which might allow remote attackers to conduct
cross-site scripting (XSS) attacks via unspecified vectors.
CVE-2011-3059
Google Chrome before 18.0.1025.142 does not properly handle SVG text
elements, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2011-3060
Google Chrome before 18.0.1025.142 does not properly handle text
fragments, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2011-3061
Google Chrome before 18.0.1025.142 does not properly check X.509
certificates before use of a SPDY proxy, which might allow
man-in-the-middle attackers to spoof servers or obtain sensitive
information via a crafted certificate.
CVE-2011-3062
Off-by-one error in the OpenType Sanitizer in Google Chrome before
18.0.1025.142 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via a crafted OpenType file.
CVE-2011-3063
Google Chrome before 18.0.1025.142 does not properly validate the
renderer's navigation requests, which has unspecified impact and
remote attack vectors.
CVE-2011-3064
Use-after-free vulnerability in Google Chrome before 18.0.1025.142
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to SVG clipping.
CVE-2011-3065
Skia, as used in Google Chrome before 18.0.1025.142, allows remote
attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via unknown vectors." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/search/label/Stable%20updates" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/b8f0a391-7910-11e1-8a43-00262d5ed8ee.html" );
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
if(!isnull( bver ) && revcomp( a: bver, b: "18.0.1025.142" ) < 0){
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

