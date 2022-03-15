if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702737" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2161", "CVE-2013-4155" );
	script_name( "Debian Security Advisory DSA 2737-1 (swift - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-08-12 00:00:00 +0200 (Mon, 12 Aug 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2737.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "swift on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 1.4.8-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.0-6.

We recommend that you upgrade your swift packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Swift, the Openstack
object storage. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2013-2161
Alex Gaynor from Rackspace reported a vulnerability in XML
handling within Swift account servers. Account strings were
unescaped in xml listings, and an attacker could potentially
generate unparsable or arbitrary XML responses which may be
used to leverage other vulnerabilities in the calling software.

CVE-2013-4155
Peter Portante from Red Hat reported a vulnerability in Swift.
By issuing requests with an old X-Timestamp value, an
authenticated attacker can fill an object server with superfluous
object tombstones, which may significantly slow down subsequent
requests to that object server, facilitating a Denial of Service
attack against Swift clusters." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-swift", ver: "1.4.8-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swift", ver: "1.4.8-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swift-account", ver: "1.4.8-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swift-container", ver: "1.4.8-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swift-doc", ver: "1.4.8-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swift-object", ver: "1.4.8-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swift-proxy", ver: "1.4.8-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

