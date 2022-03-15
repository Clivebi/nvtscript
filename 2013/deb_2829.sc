if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702829" );
	script_version( "$Revision: 14276 $" );
	script_cve_id( "CVE-2013-0200", "CVE-2013-4325", "CVE-2013-6402", "CVE-2013-6427" );
	script_name( "Debian Security Advisory DSA 2829-1 (hplip - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-28 00:00:00 +0100 (Sat, 28 Dec 2013)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2829.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "hplip on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 3.10.6-2+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in
version 3.12.6-3.1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 3.13.11-2.

We recommend that you upgrade your hplip packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found in the HP Linux Printing and
Imaging System: Insecure temporary files, insufficient permission checks
in PackageKit and the insecure hp-upgrade service has been disabled." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "hpijs", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hpijs-ppds", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-cups", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-data", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-dbg", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-doc", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-gui", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libhpmud-dev", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libhpmud0", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsane-hpaio", ver: "3.10.6-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hpijs", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hpijs-ppds", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-cups", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-data", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-dbg", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-doc", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hplip-gui", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libhpmud-dev", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libhpmud0", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsane-hpaio", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "printer-driver-hpcups", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "printer-driver-hpijs", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "printer-driver-postscript-hp", ver: "3.12.6-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
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

