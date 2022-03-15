if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702994" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-1741", "CVE-2013-5606", "CVE-2014-1491", "CVE-2014-1492" );
	script_name( "Debian Security Advisory DSA 2994-1 (nss - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-31 00:00:00 +0200 (Thu, 31 Jul 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2994.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "nss on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 2:3.14.5-1+deb7u1.

For the testing distribution (jessie), and the unstable distribution (sid),
these problems have been fixed in version 2:3.16-1.

We recommend that you upgrade your nss packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in nss, the Mozilla Network
Security Service library:

CVE-2013-1741
Runaway memset in certificate parsing on 64-bit computers leading to
a crash by attempting to write 4Gb of nulls.

CVE-2013-5606
Certificate validation with the verifylog mode did not return
validation errors, but instead expected applications to determine
the status by looking at the log.

CVE-2014-1491
Ticket handling protection mechanisms bypass due to the lack of
restriction of public values in Diffie-Hellman key exchanges.

CVE-2014-1492
Incorrect IDNA domain name matching for wildcard certificates could
allow specially-crafted invalid certificates to be considered as
valid." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.14.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "2:3.14.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dbg", ver: "2:3.14.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "2:3.14.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "2:3.14.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
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
