if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890814" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2016-7056", "CVE-2016-8610", "CVE-2017-3731" );
	script_name( "Debian LTS: Security Advisory for openssl (DLA-814-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-05 00:00:00 +0100 (Fri, 05 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/02/msg00001.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.0.1t-1+deb7u2.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in OpenSSL:

CVE-2016-7056

A local timing attack was discovered against ECDSA P-256.

CVE-2016-8610

It was discovered that no limit was imposed on alert packets during
an SSL handshake.

CVE-2017-3731

Robert Swiecki discovered that the RC4-MD5 cipher when running on
32 bit systems could be forced into an out-of-bounds read, resulting
in denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1t-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1t-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1t-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1t-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1t-1+deb7u2", rls: "DEB7" ) )){
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

