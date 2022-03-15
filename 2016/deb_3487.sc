if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703487" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-0787" );
	script_name( "Debian Security Advisory DSA 3487-1 (libssh2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:47 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3487.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7)" );
	script_tag( name: "affected", value: "libssh2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 1.4.2-1.1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 1.4.3-4.1+deb8u1.

We recommend that you upgrade your libssh2 packages." );
	script_tag( name: "summary", value: "Andreas Schneider reported that libssh2, a SSH2 client-side library,
passes the number of bytes to a function that expects number of bits
during the SSHv2 handshake when libssh2 is to get a suitable value for
group order
in the Diffie-Hellman negotiation. This weakens
significantly the handshake security, potentially allowing an
eavesdropper with enough resources to decrypt or intercept SSH sessions." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libssh2-1", ver: "1.4.3-4.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh2-1-dbg", ver: "1.4.3-4.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh2-1-dev", ver: "1.4.3-4.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh2-1", ver: "1.4.2-1.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh2-1-dbg", ver: "1.4.2-1.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh2-1-dev", ver: "1.4.2-1.1+deb7u2", rls: "DEB7" ) ) != NULL){
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

