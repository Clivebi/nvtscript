if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703129" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2013-6435", "CVE-2014-8118" );
	script_name( "Debian Security Advisory DSA 3129-1 (rpm - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-15 00:00:00 +0100 (Thu, 15 Jan 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3129.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "rpm on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 4.10.0-5+deb7u2.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 4.11.3-1.1.

For the unstable distribution (sid), these problems have been fixed in
version 4.11.3-1.1.

We recommend that you upgrade your rpm packages." );
	script_tag( name: "summary", value: "Two vulnerabilities have been discovered
in the RPM package manager.

CVE-2013-6435
Florian Weimer discovered a race condition in package signature
validation.

CVE-2014-8118
Florian Weimer discovered an integer overflow in parsing CPIO headers
which might result in the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "librpm-dbg", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librpm-dev", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librpm3", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librpmbuild3", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librpmio3", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librpmsign1", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-rpm", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rpm", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rpm-common", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rpm-i18n", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rpm2cpio", ver: "4.10.0-5+deb7u2", rls: "DEB7" ) ) != NULL){
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

