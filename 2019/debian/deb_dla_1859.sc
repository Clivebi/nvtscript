if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891859" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2018-5743" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-18 18:15:00 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-07-22 02:00:07 +0000 (Mon, 22 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for bind9 (DLA-1859-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1859-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind9'
  package(s) announced via the DLA-1859-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was found in the Bind DNS Server. Limits on
simultaneous tcp connections have not been enforced correctly and could
lead to exhaustion of file descriptors. In the worst case this could
affect the file descriptors of the whole system." );
	script_tag( name: "affected", value: "'bind9' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1:9.9.5.dfsg-9+deb8u18.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bind9", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "host", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind-export-dev", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind9-90", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdns-export100", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdns100", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libirs-export91", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisc-export95", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisc95", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccc90", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccfg-export90", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccfg90", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblwres90", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.9.5.dfsg-9+deb8u18", rls: "DEB8" ) )){
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

