if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704065" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-3737", "CVE-2017-3738" );
	script_name( "Debian Security Advisory DSA 4065-1 (openssl1.0 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-17 00:00:00 +0100 (Sun, 17 Dec 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4065.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "openssl1.0 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1.0.2l-2+deb9u2.

We recommend that you upgrade your openssl1.0 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/openssl1.0" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in OpenSSL, a Secure
Sockets Layer toolkit. The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2017-3737
David Benjamin of Google reported that OpenSSL does not properly
handle SSL_read() and SSL_write() while being invoked in an error
state, causing data to be passed without being decrypted or
encrypted directly from the SSL/TLS record layer.

CVE-2017-3738
It was discovered that OpenSSL contains an overflow bug in the AVX2
Montgomery multiplication procedure used in exponentiation with
1024-bit moduli." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0-dev", ver: "1.0.2l-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.2", ver: "1.0.2l-2+deb9u2", rls: "DEB9" ) )){
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

