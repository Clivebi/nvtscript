if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704130" );
	script_version( "2021-06-16T13:21:12+0000" );
	script_cve_id( "CVE-2017-14461", "CVE-2017-15130", "CVE-2017-15132" );
	script_name( "Debian Security Advisory DSA 4130-1 (dovecot - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 13:21:12 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-02 00:00:00 +0100 (Fri, 02 Mar 2018)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-04 01:29:00 +0000 (Wed, 04 Apr 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4130.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "dovecot on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1:2.2.13-12~deb8u4.

For the stable distribution (stretch), these problems have been fixed in
version 1:2.2.27-3+deb9u2.

We recommend that you upgrade your dovecot packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/dovecot" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Dovecot email
server. The Common Vulnerabilities and Exposures project identifies the
following issues:

CVE-2017-14461Aleksandar Nikolic of Cisco Talos and flxflndy
discovered that
Dovecot does not properly parse invalid email addresses, which may
cause a crash or leak memory contents to an attacker.

CVE-2017-15130It was discovered that TLS SNI config lookups may lead to excessive
memory usage, causing imap-login/pop3-login VSZ limit to be reached
and the process restarted, resulting in a denial of service. Only
Dovecot configurations containing local_name { } or local { }

configuration blocks are affected.

CVE-2017-15132
It was discovered that Dovecot contains a memory leak flaw in the
login process on aborted SASL authentication." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dovecot-core", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-dbg", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-dev", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-gssapi", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-imapd", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-ldap", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-lmtpd", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-lucene", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-managesieved", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-mysql", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-pgsql", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-pop3d", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-sieve", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-solr", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-sqlite", ver: "1:2.2.27-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-core", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-dbg", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-dev", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-gssapi", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-imapd", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-ldap", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-lmtpd", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-lucene", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-managesieved", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-mysql", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-pgsql", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-pop3d", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-sieve", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-solr", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-sqlite", ver: "1:2.2.13-12~deb8u4", rls: "DEB8" ) )){
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

