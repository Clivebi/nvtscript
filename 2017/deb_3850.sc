if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703850" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2015-8270", "CVE-2015-8271", "CVE-2015-8272" );
	script_name( "Debian Security Advisory DSA 3850-1 (rtmpdump - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-12 00:00:00 +0200 (Fri, 12 May 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3850.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "rtmpdump on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 2.4+20150115.gita107cef-1+deb8u1.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 2.4+20151223.gitfa8646d.1-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.4+20151223.gitfa8646d.1-1.

We recommend that you upgrade your rtmpdump packages." );
	script_tag( name: "summary", value: "Dave McDaniel discovered multiple vulnerabilities in rtmpdump, a small
dumper/library for RTMP media streams, which may result in denial of
service or the execution of arbitrary code if a malformed stream is
dumped." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "librtmp-dev", ver: "2.4+20150115.gita107cef-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librtmp1", ver: "2.4+20150115.gita107cef-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rtmpdump", ver: "2.4+20150115.gita107cef-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librtmp-dev", ver: "2.4+20151223.gitfa8646d.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "librtmp1", ver: "2.4+20151223.gitfa8646d.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rtmpdump", ver: "2.4+20151223.gitfa8646d.1-1", rls: "DEB9" ) ) != NULL){
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

