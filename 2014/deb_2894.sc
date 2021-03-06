if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702894" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-2532", "CVE-2014-2653" );
	script_name( "Debian Security Advisory DSA 2894-1 (openssh - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-05 00:00:00 +0200 (Sat, 05 Apr 2014)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2894.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "openssh on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 1:5.5p1-6+squeeze5.

For the stable distribution (wheezy), these problems have been fixed in
version 1:6.0p1-4+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1:6.6p1-1.

We recommend that you upgrade your openssh packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in OpenSSH, an implementation of the
SSH protocol suite. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2014-2532
Jann Horn discovered that OpenSSH incorrectly handled wildcards in
AcceptEnv lines. A remote attacker could use this issue to trick
OpenSSH into accepting any environment variable that contains the
characters before the wildcard character.

CVE-2014-2653
Matthew Vernon reported that if a SSH server offers a
HostCertificate that the ssh client doesn't accept, then the client
doesn't check the DNS for SSHFP records. As a consequence a
malicious server can disable SSHFP-checking by presenting a
certificate.

Note that a host verification prompt is still displayed before
connecting." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openssh-client", ver: "1:5.5p1-6+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssh-server", ver: "1:5.5p1-6+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh", ver: "1:5.5p1-6+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh-askpass-gnome", ver: "1:5.5p1-6+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh-krb5", ver: "1:5.5p1-6+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssh-client", ver: "1:6.0p1-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssh-server", ver: "1:6.0p1-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh", ver: "1:6.0p1-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh-askpass-gnome", ver: "1:6.0p1-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh-krb5", ver: "1:6.0p1-4+deb7u1", rls: "DEB7" ) ) != NULL){
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

