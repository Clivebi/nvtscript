if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891668" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-1000019", "CVE-2019-1000020" );
	script_name( "Debian LTS: Security Advisory for libarchive (DLA-1668-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-08 00:00:00 +0100 (Fri, 08 Feb 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 01:15:00 +0000 (Wed, 06 Nov 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00013.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libarchive on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.1.2-11+deb8u7.

We recommend that you upgrade your libarchive packages." );
	script_tag( name: "summary", value: "Fuzzing found two further file-format specific issues in libarchive, a
read-only segfault in 7z, and an infinite loop in ISO9660.

CVE-2019-1000019

Out-of-bounds Read vulnerability in 7zip decompression, that can
result in a crash (denial of service, CWE-125)

CVE-2019-1000020

Vulnerability in ISO9660 parser that can result in DoS by infinite
loop (CWE-835)" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.1.2-11+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bsdtar", ver: "3.1.2-11+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive-dev", ver: "3.1.2-11+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive13", ver: "3.1.2-11+deb8u7", rls: "DEB8" ) )){
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

