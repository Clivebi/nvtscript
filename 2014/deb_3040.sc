if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703040" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3634" );
	script_name( "Debian Security Advisory DSA 3040-1 (rsyslog - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-30 00:00:00 +0200 (Tue, 30 Sep 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3040.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "rsyslog on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 5.8.11-3+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 8.4.1-1.

We recommend that you upgrade your rsyslog packages." );
	script_tag( name: "summary", value: "Rainer Gerhards, the rsyslog project leader, reported a vulnerability in
Rsyslog, a system for log processing. As a consequence of this
vulnerability an attacker can send malformed messages to a server, if
this one accepts data from untrusted sources, and trigger a denial of
service attack." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rsyslog", ver: "5.8.11-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rsyslog-doc", ver: "5.8.11-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rsyslog-gnutls", ver: "5.8.11-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rsyslog-gssapi", ver: "5.8.11-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rsyslog-mysql", ver: "5.8.11-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rsyslog-pgsql", ver: "5.8.11-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rsyslog-relp", ver: "5.8.11-3+deb7u1", rls: "DEB7" ) ) != NULL){
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
