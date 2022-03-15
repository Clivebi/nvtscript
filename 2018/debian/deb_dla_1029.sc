if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891029" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2017-9831", "CVE-2017-9832" );
	script_name( "Debian LTS: Security Advisory for libmtp (DLA-1029-1)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-05 17:15:00 +0000 (Sun, 05 Apr 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00021.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libmtp on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.1.3-35-g0ece104-5+deb7u1.

We recommend that you upgrade your libmtp packages." );
	script_tag( name: "summary", value: "libmtp, a library for communicating with MTP aware devices (like
cellular phones and audio players), was found to be vulnerable to
several integer overflow vulnerabilities, which allowed malicious
devices to cause denial of service crashes and maybe remote code
execution.

CVE-2017-9831

An integer overflow vulnerability in the
ptp_unpack_EOS_CustomFuncEx function of the ptp-pack.c file of
libmtp (version 1.1.12 and below) allows attackers to cause a
denial of service (out-of-bounds memory access) or maybe remote
code execution by inserting a mobile device into a personal
computer through a USB cable.

CVE-2017-9832

An integer overflow vulnerability in ptp-pack.c (ptp_unpack_OPL
function) of libmtp (version 1.1.12 and below) allows attackers to
cause a denial of service (out-of-bounds memory access) or maybe
remote code execution by inserting a mobile device into a personal
computer through a USB cable." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmtp-common", ver: "1.1.3-35-g0ece104-5+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmtp-dbg", ver: "1.1.3-35-g0ece104-5+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmtp-dev", ver: "1.1.3-35-g0ece104-5+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmtp-doc", ver: "1.1.3-35-g0ece104-5+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmtp-runtime", ver: "1.1.3-35-g0ece104-5+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmtp9", ver: "1.1.3-35-g0ece104-5+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mtp-tools", ver: "1.1.3-35-g0ece104-5+deb7u1", rls: "DEB7" ) )){
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

