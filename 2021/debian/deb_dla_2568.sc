if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892568" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_cve_id( "CVE-2020-8625" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-19 22:15:00 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-20 04:00:08 +0000 (Sat, 20 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for bind9 (DLA-2568-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2568-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2568-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/983004" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind9'
  package(s) announced via the DLA-2568-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a buffer overflow attack in the
bind9 DNS server caused by an issue in the GSSAPI ('Generic Security
Services') security policy negotiation." );
	script_tag( name: "affected", value: "'bind9' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
1:9.10.3.dfsg.P4-12.3+deb9u8.

We recommend that you upgrade your bind9 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bind9", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "host", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind-export-dev", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbind9-140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdns-export162", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdns162", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libirs-export141", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libirs141", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisc-export160", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisc160", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccc-export140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccc140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccfg-export140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libisccfg140", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblwres141", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.10.3.dfsg.P4-12.3+deb9u8", rls: "DEB9" ) )){
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

