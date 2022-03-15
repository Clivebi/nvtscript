if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891477" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2018-10887", "CVE-2018-10888", "CVE-2018-15501" );
	script_name( "Debian LTS: Security Advisory for libgit2 (DLA-1477-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-26 00:00:00 +0200 (Sun, 26 Aug 2018)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-31 15:56:00 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00024.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libgit2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.21.1-3+deb8u1.

We recommend that you upgrade your libgit2 packages." );
	script_tag( name: "summary", value: "CVE-2018-15501
A potential out-of-bounds read when processing a 'ng' smart packet
might lead to a Denial of Service.

CVE-2018-10887
A flaw has been discovered that may lead to an integer overflow which
in turn leads to an out of bound read, allowing to read before the
base object. This might be used to leak memory addresses or cause a
Denial of Service.

CVE-2018-10888
A flaw may lead to an out-of-bound read while reading a binary delta
file. This might result in a Denial of Service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libgit2-21", ver: "0.21.1-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgit2-dbg", ver: "0.21.1-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgit2-dev", ver: "0.21.1-3+deb8u1", rls: "DEB8" ) )){
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

