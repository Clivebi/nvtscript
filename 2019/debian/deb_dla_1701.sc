if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891701" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-1559" );
	script_name( "Debian LTS: Security Advisory for openssl (DLA-1701-1)" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-04 00:00:00 +0100 (Mon, 04 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00003.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.0.1t-1+deb8u11.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "Juraj Somorovsky, Robert Merget and Nimrod Aviram discovered a padding
oracle attack in OpenSSL.

If an application encounters a fatal protocol error and then calls
SSL_shutdown() twice (once to send a close_notify, and once to receive
one) then OpenSSL can respond differently to the calling application
if a 0 byte record is received with invalid padding compared to if a 0
byte record is received with an invalid MAC. If the application then
behaves differently based on that in a way that is detectable to the
remote peer, then this amounts to a padding oracle that could be used
to decrypt data.

In order for this to be exploitable 'non-stitched' ciphersuites must
be in use. Stitched ciphersuites are optimised implementations of
certain commonly used ciphersuites. Also the application must call
SSL_shutdown() twice even if a protocol error has occurred
(applications should not do this but some do anyway).
AEAD ciphersuites are not impacted." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1t-1+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1t-1+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1t-1+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1t-1+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1t-1+deb8u11", rls: "DEB8" ) )){
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

