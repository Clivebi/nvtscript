if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704591" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-19906" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-12-21 03:00:05 +0000 (Sat, 21 Dec 2019)" );
	script_name( "Debian Security Advisory DSA 4591-1 (cyrus-sasl2 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4591.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4591-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cyrus-sasl2'
  package(s) announced via the DSA-4591-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Stephan Zeisberg reported an out-of-bounds write vulnerability in the
_sasl_add_string() function in cyrus-sasl2, a library implementing the
Simple Authentication and Security Layer. A remote attacker can take
advantage of this issue to cause denial-of-service conditions for
applications using the library." );
	script_tag( name: "affected", value: "'cyrus-sasl2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 2.1.27~101-g0780600+dfsg-3+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 2.1.27+dfsg-1+deb10u1.

We recommend that you upgrade your cyrus-sasl2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cyrus-sasl2-doc", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-2", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-dev", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-db", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-gssapi-heimdal", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-gssapi-mit", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-ldap", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-otp", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-sql", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sasl2-bin", ver: "2.1.27~101-g0780600+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-sasl2-doc", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-2", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-dev", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-db", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-gssapi-heimdal", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-gssapi-mit", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-ldap", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-otp", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-sql", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sasl2-bin", ver: "2.1.27+dfsg-1+deb10u1", rls: "DEB10" ) )){
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
exit( 0 );

