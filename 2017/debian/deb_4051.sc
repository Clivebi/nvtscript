if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704051" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_cve_id( "CVE-2017-8816", "CVE-2017-8817" );
	script_name( "Debian Security Advisory DSA 4051-1 (curl - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-29 00:00:00 +0100 (Wed, 29 Nov 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4051.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "curl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 7.38.0-4+deb8u8.

For the stable distribution (stretch), these problems have been fixed in
version 7.52.1-5+deb9u3.

We recommend that you upgrade your curl packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/curl" );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in cURL, an URL transfer library.

CVE-2017-8816
Alex Nichols discovered a buffer overrun flaw in the NTLM authentication
code which can be triggered on 32bit systems where an integer overflow
might occur when calculating the size of a memory allocation.

CVE-2017-8817
Fuzzing by the OSS-Fuzz project led to the discovery of a read out of
bounds flaw in the FTP wildcard function in libcurl. A malicious server
could redirect a libcurl-based client to an URL using a wildcard pattern,
triggering the out-of-bound read." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.38.0-4+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.52.1-5+deb9u3", rls: "DEB9" ) )){
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

