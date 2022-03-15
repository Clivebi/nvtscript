if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704881" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-8169", "CVE-2020-8177", "CVE-2020-8231", "CVE-2020-8284", "CVE-2020-8285", "CVE-2020-8286", "CVE-2021-22876", "CVE-2021-22890" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-08 20:00:00 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-01 03:00:20 +0000 (Thu, 01 Apr 2021)" );
	script_name( "Debian: Security Advisory for curl (DSA-4881-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4881.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4881-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4881-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the DSA-4881-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in cURL, an URL transfer library:

CVE-2020-8169
Marek Szlagor reported that libcurl could be tricked into prepending
a part of the password to the host name before it resolves it,
potentially leaking the partial password over the network and to the
DNS server(s).

CVE-2020-8177
sn reported that curl could be tricked by a malicious server into
overwriting a local file when using the -J (--remote-header-name) and -i
(--include) options in the same command line.

CVE-2020-8231
Marc Aldorasi reported that libcurl might use the wrong connection
when an application using libcurl's multi API sets the option
CURLOPT_CONNECT_ONLY, which could lead to information leaks.

CVE-2020-8284
Varnavas Papaioannou reported that a malicious server could use the
PASV response to trick curl into connecting back to an arbitrary IP
address and port, potentially making curl extract information about
services that are otherwise private and not disclosed.

CVE-2020-8285
xnynx reported that libcurl could run out of stack space when using
the FTP wildcard matching functionality (CURLOPT_CHUNK_BGN_FUNCTION).

CVE-2020-8286
It was reported that libcurl didn't verify that an OCSP response
actually matches the certificate it is intended to.

CVE-2021-22876
Viktor Szakats reported that libcurl does not strip off user
credentials from the URL when automatically populating the Referer
HTTP request header field in outgoing HTTP requests.

CVE-2021-22890
Mingtao Yang reported that, when using an HTTPS proxy and TLS 1.3,
libcurl could confuse session tickets arriving from the HTTPS proxy
as if they arrived from the remote server instead. This could allow
an HTTPS proxy to trick libcurl into using the wrong session ticket
for the host and thereby circumvent the server TLS certificate check." );
	script_tag( name: "affected", value: "'curl' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 7.64.0-4+deb10u2.

We recommend that you upgrade your curl packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.64.0-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.64.0-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.64.0-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4", ver: "7.64.0-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.64.0-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.64.0-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.64.0-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.64.0-4+deb10u2", rls: "DEB10" ) )){
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

