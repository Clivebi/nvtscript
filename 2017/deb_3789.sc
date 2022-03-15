if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703789" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_cve_id( "CVE-2016-10195", "CVE-2016-10196", "CVE-2016-10197" );
	script_name( "Debian Security Advisory DSA 3789-1 (libevent - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-15 00:00:00 +0100 (Wed, 15 Feb 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3789.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libevent on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 2.0.21-stable-2+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 2.0.21-stable-3.

We recommend that you upgrade your libevent packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in libevent, an asynchronous event notification library. They would lead to Denial
Of Service via application crash, or remote code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libevent-2.0-5:amd64", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-2.0-5:i386", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-core-2.0-5:amd64", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-core-2.0-5:i386", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-dbg:amd64", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-dbg:i386", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-dev", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-extra-2.0-5:amd64", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-extra-2.0-5:i386", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-openssl-2.0-5:amd64", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-openssl-2.0-5:i386", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-pthreads-2.0-5:amd64", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libevent-pthreads-2.0-5:i386", ver: "2.0.21-stable-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

