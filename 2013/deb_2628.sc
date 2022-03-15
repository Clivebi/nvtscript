if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702628" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-0288" );
	script_name( "Debian Security Advisory DSA 2628-1 (nss-pam-ldapd - buffer overflow)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-06-18 00:00:00 +0200 (Tue, 18 Jun 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2628.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "nss-pam-ldapd on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze) this problem has been fixed in
version 0.7.15+squeeze4.

For the testing distribution (wheezy), this problem has been fixed in
version 0.8.10-3.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.10-3.

We recommend that you upgrade your nss-pam-ldapd packages." );
	script_tag( name: "summary", value: "Garth Mollett discovered that a file descriptor overflow issue in the
use of FD_SET() in nss-pam-ldapd, which provides NSS and PAM modules for
using LDAP as a naming service, can lead to a stack-based buffer
overflow. An attacker could, under some circumstances, use this flaw to
cause a process that has the NSS or PAM module loaded to crash or
potentially execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss-ldapd", ver: "0.7.15+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-ldapd", ver: "0.7.15+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nslcd", ver: "0.7.15+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss-ldapd", ver: "0.8.10-3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-ldapd", ver: "0.8.10-3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nslcd", ver: "0.8.10-3", rls: "DEB7" ) ) != NULL){
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

