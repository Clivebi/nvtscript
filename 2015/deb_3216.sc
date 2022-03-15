if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703216" );
	script_version( "2020-02-04T09:04:16+0000" );
	script_cve_id( "CVE-2015-2928", "CVE-2015-2929" );
	script_name( "Debian Security Advisory DSA 3216-1 (tor - security update)" );
	script_tag( name: "last_modification", value: "2020-02-04 09:04:16 +0000 (Tue, 04 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-04-06 00:00:00 +0200 (Mon, 06 Apr 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3216.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "tor on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 0.2.4.27-1.

For the unstable distribution (sid), these problems have been fixed in
version 0.2.5.12-1.

For the experimental distribution, these problems have been
fixed in version 0.2.6.7-1.

We recommend that you upgrade your tor packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have
been discovered in Tor, a connection-based low-latency anonymous
communication system:

CVE-2015-2928disgleirio
discovered that a malicious client could trigger an
assertion failure in a Tor instance providing a hidden service,
thus rendering the service inaccessible.

CVE-2015-2929DonnchaC
discovered that Tor clients would crash with an
assertion failure upon parsing specially crafted hidden service
descriptors.

Introduction points would accept multiple INTRODUCE1 cells on one
circuit, making it inexpensive for an attacker to overload a hidden
service with introductions. Introduction points now no longer allow
multiple cells of that type on the same circuit." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tor", ver: "0.2.4.27-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-dbg", ver: "0.2.4.27-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.2.4.27-1", rls: "DEB7" ) ) != NULL){
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

