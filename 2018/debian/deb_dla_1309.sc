if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891309" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2018-1000120", "CVE-2018-1000121", "CVE-2018-1000122" );
	script_name( "Debian LTS: Security Advisory for curl (DLA-1309-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 22:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "curl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
7.26.0-1+wheezy25.

We recommend that you upgrade your curl packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were found in cURL, an URL transfer library:

CVE-2018-1000120

Duy Phan Thanh reported that curl could be fooled into writing a zero byte
out of bounds when curl was told to work on an FTP URL, with the setting to
only issue a single CWD command. The issue could be triggered if the
directory part of the URL contained a '%00' sequence.

CVE-2018-1000121

Dario Weisser reported that curl might dereference a near-NULL address when
getting an LDAP URL. A malicious server that sends a particularly crafted
response could made crash applications that allowed LDAP URL relying on
libcurl.

CVE-2018-1000122

OSS-fuzz and Max Dymond found that curl can be tricked into copying data
beyond the end of its heap based buffer when asked to transfer an RTSP URL.
curl could calculate a wrong data length to copy from the read buffer.
This could lead to information leakage or a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.26.0-1+wheezy25", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3", ver: "7.26.0-1+wheezy25", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.26.0-1+wheezy25", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.26.0-1+wheezy25", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.26.0-1+wheezy25", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.26.0-1+wheezy25", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.26.0-1+wheezy25", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.26.0-1+wheezy25", rls: "DEB7" ) )){
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

