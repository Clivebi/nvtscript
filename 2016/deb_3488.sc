if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703488" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2014-8132", "CVE-2015-3146", "CVE-2016-0739" );
	script_name( "Debian Security Advisory DSA 3488-1 (libssh - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:45 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3488.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "libssh on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed in
version 0.5.4-1+deb7u3. This update also includes fixes for
CVE-2014-8132 and CVE-2015-3146
,
which were previously scheduled for the next wheezy point release.

For the stable distribution (jessie), this problem has been fixed in
version 0.6.3-4+deb8u2.

We recommend that you upgrade your libssh packages." );
	script_tag( name: "summary", value: "Aris Adamantiadis discovered that libssh, a tiny C SSH library,
incorrectly generated a short ephemeral secret for the
diffie-hellman-group1 and diffie-hellman-group14 key exchange methods.
The resulting secret is 128 bits long, instead of the recommended sizes
of 1024 and 2048 bits respectively. This flaw could allow an
eavesdropper with enough resources to decrypt or intercept SSH sessions." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.5.4-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dbg", ver: "0.5.4-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dev", ver: "0.5.4-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-doc", ver: "0.5.4-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.6.3-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dbg", ver: "0.6.3-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dev", ver: "0.6.3-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-doc", ver: "0.6.3-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-gcrypt-4", ver: "0.6.3-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-gcrypt-dev", ver: "0.6.3-4+deb8u2", rls: "DEB8" ) ) != NULL){
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

