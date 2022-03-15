if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70747" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3924", "CVE-2011-3926", "CVE-2011-3927", "CVE-2011-3928" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: chromium" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: chromium

CVE-2011-3924
Use-after-free vulnerability in Google Chrome before 16.0.912.77
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to DOM selections.

CVE-2011-3926
Heap-based buffer overflow in the tree builder in Google Chrome before
16.0.912.77 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors.

CVE-2011-3927
Skia, as used in Google Chrome before 16.0.912.77, does not perform
all required initialization of values, which allows remote attackers
to cause a denial of service or possibly have unspecified other impact
via unknown vectors.

CVE-2011-3928
Use-after-free vulnerability in Google Chrome before 16.0.912.77
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to DOM handling." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/search/label/Stable%20updates" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/33d73d59-4677-11e1-88cd-00262d5ed8ee.html" );
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
if(!isnull( bver ) && revcomp( a: bver, b: "16.0.912.77" ) < 0){
	txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
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

