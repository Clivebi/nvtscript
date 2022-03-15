if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704017" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-3735", "CVE-2017-3736" );
	script_name( "Debian Security Advisory DSA 4017-1 (openssl1.0 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-03 00:00:00 +0100 (Fri, 03 Nov 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "openssl1.0 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1.0.2l-2+deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.2m-1.

We recommend that you upgrade your openssl1.0 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in OpenSSL, a Secure
Sockets Layer toolkit. The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2017-3735
It was discovered that OpenSSL is prone to a one-byte buffer
overread while parsing a malformed IPAddressFamily extension in an
X.509 certificate.

CVE-2017-3736
It was discovered that OpenSSL contains a carry propagation bug in
the x86_64 Montgomery squaring procedure." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libssl1.0-dev", ver: "1.0.2l-2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.2", ver: "1.0.2l-2+deb9u1", rls: "DEB9" ) ) != NULL){
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

