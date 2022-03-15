if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891520" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-1000158", "CVE-2018-1000802", "CVE-2018-1060", "CVE-2018-1061" );
	script_name( "Debian LTS: Security Advisory for python3.4 (DLA-1520-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-26 00:00:00 +0200 (Wed, 26 Sep 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00031.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "python3.4 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.4.2-1+deb8u1.

We recommend that you upgrade your python3.4 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were found in the CPython interpreter which
can cause denial of service, information gain, and arbitrary code
execution.

CVE-2017-1000158

CPython (aka Python) is vulnerable to an integer overflow in the
PyString_DecodeEscape function in stringobject.c, resulting in
heap-based buffer overflow (and possible arbitrary code execution)

CVE-2018-1060

python is vulnerable to catastrophic backtracking in pop3lib's
apop() method. An attacker could use this flaw to cause denial of
service.

CVE-2018-1061

python is vulnerable to catastrophic backtracking in the
difflib.IS_LINE_JUNK method. An attacker could use this flaw to
cause denial of service.

CVE-2018-1000802

Python Software Foundation Python (CPython) version 2.7 contains a
CWE-77: Improper Neutralization of Special Elements used in a
Command ('Command Injection') vulnerability in shutil module
(make_archive function) that can result in Denial of service,
Information gain via injection of arbitrary files on the system or
entire drive. This attack appear to be exploitable via Passage of
unfiltered user input to the function." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "idle-python3.4", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-dbg", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-dev", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-minimal", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-stdlib", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython3.4-testsuite", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-dbg", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-dev", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-doc", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-examples", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-minimal", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3.4-venv", ver: "3.4.2-1+deb8u1", rls: "DEB8" ) )){
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

