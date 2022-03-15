if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892044" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-19906" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-12-21 03:00:12 +0000 (Sat, 21 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for cyrus-sasl2 (DLA-2044-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2044-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/947043" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cyrus-sasl2'
  package(s) announced via the DLA-2044-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "There has been an out-of-bounds write in Cyrus SASL leading to
unauthenticated remote denial-of-service in OpenLDAP via a malformed LDAP
packet. The OpenLDAP crash was ultimately caused by an off-by-one error
in _sasl_add_string in common.c in cyrus-sasl." );
	script_tag( name: "affected", value: "'cyrus-sasl2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.1.26.dfsg1-13+deb8u2.

We recommend that you upgrade your cyrus-sasl2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cyrus-sasl2-dbg", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-sasl2-doc", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-sasl2-heimdal-dbg", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-sasl2-mit-dbg", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-2", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-dev", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-db", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-gssapi-heimdal", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-gssapi-mit", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-ldap", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-otp", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsasl2-modules-sql", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sasl2-bin", ver: "2.1.26.dfsg1-13+deb8u2", rls: "DEB8" ) )){
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

