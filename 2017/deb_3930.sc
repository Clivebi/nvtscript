if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703930" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_cve_id( "CVE-2017-10978", "CVE-2017-10979", "CVE-2017-10980", "CVE-2017-10981", "CVE-2017-10982", "CVE-2017-10983", "CVE-2017-10984", "CVE-2017-10985", "CVE-2017-10986", "CVE-2017-10987" );
	script_name( "Debian Security Advisory DSA 3930-1 (freeradius - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-10 00:00:00 +0200 (Thu, 10 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3930.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "freeradius on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2.2.5+dfsg-0.2+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 3.0.12+dfsg-5+deb9u1.

We recommend that you upgrade your freeradius packages." );
	script_tag( name: "summary", value: "Guido Vranken discovered that FreeRADIUS, an open source
implementation of RADIUS, the IETF protocol for AAA (Authorisation,
Authentication, and Accounting), did not properly handle memory when
processing packets. This would allow a remote attacker to cause a
denial-of-service by application crash, or potentially execute
arbitrary code.

All those issues are covered by this single DSA, but it's worth noting
that not all issues affect all releases:

CVE-2017-10978 and CVE-2017-10983 affect both jessie and stretch. CVE-2017-10979, CVE-2017-10980, CVE-2017-10981 and CVE-2017-10982 affect only jessie.
CVE-2017-10984, CVE-2017-10985, CVE-2017-10986 and CVE-2017-10987 affect only stretch." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "freeradius", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-common", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-config", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-dhcp", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-iodbc", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-krb5", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-ldap", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-memcached", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-mysql", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-postgresql", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-redis", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-rest", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-utils", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-yubikey", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeradius-dev", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeradius3", ver: "3.0.12+dfsg-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-common", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-dbg", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-iodbc", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-krb5", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-ldap", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-mysql", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-postgresql", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-utils", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeradius-dev", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeradius2", ver: "2.2.5+dfsg-0.2+deb8u1", rls: "DEB8" ) ) != NULL){
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

