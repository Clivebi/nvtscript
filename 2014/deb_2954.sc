if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702954" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3430" );
	script_name( "Debian Security Advisory DSA 2954-1 (dovecot - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-09 00:00:00 +0200 (Mon, 09 Jun 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2954.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "dovecot on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1:2.1.7-7+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1:2.2.13~rc1-1.

For the unstable distribution (sid), this problem has been fixed in
version 1:2.2.13~rc1-1.

We recommend that you upgrade your dovecot packages." );
	script_tag( name: "summary", value: "It was discovered that the Dovecot email server is vulnerable to a
denial of service attack against imap/pop3-login processes due to
incorrect handling of the closure of inactive SSL/TLS connections." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dovecot-common", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-core", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-dbg", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-dev", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-gssapi", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-imapd", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-ldap", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-lmtpd", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-managesieved", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-mysql", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-pgsql", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-pop3d", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-sieve", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-solr", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dovecot-sqlite", ver: "1:2.1.7-7+deb7u1", rls: "DEB7" ) ) != NULL){
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

