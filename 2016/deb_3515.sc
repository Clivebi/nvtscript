if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703515" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802" );
	script_name( "Debian Security Advisory DSA 3515-1 (graphite2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-13 00:00:00 +0100 (Sun, 13 Mar 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3515.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8|7)" );
	script_tag( name: "affected", value: "graphite2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1.3.6-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 1.3.6-1~deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1.3.6-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.3.6-1.

We recommend that you upgrade your graphite2 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found
in the Graphite font rendering engine which might result in denial of service or
the execution of arbitrary code if a malformed font file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgraphite2-3:amd64", ver: "1.3.6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-3:i386", ver: "1.3.6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-dev", ver: "1.3.6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-doc", ver: "1.3.6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-3:amd64", ver: "1.3.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-3:i386", ver: "1.3.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-3-dbg", ver: "1.3.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-dev", ver: "1.3.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-doc", ver: "1.3.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-2.0.0:amd64", ver: "1.3.6-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-2.0.0:i386", ver: "1.3.6-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-2.0.0-dbg", ver: "1.3.6-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-dev", ver: "1.3.6-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-doc", ver: "1.3.6-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

