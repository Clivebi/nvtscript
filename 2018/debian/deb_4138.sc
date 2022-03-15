if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704138" );
	script_version( "2021-06-16T13:21:12+0000" );
	script_cve_id( "CVE-2017-18187", "CVE-2018-0487", "CVE-2018-0488" );
	script_name( "Debian Security Advisory DSA 4138-1 (mbedtls - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 13:21:12 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-15 00:00:00 +0100 (Thu, 15 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-10 16:15:00 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4138.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "mbedtls on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 2.4.2-1+deb9u2.

We recommend that you upgrade your mbedtls packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/mbedtls" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in mbed TLS, a lightweight
crypto and SSL/TLS library, that allowed a remote attacker to either
cause a denial-of-service by application crash, or execute arbitrary
code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmbedcrypto0", ver: "2.4.2-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmbedtls-dev", ver: "2.4.2-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmbedtls-doc", ver: "2.4.2-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmbedtls10", ver: "2.4.2-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmbedx509-0", ver: "2.4.2-1+deb9u2", rls: "DEB9" ) )){
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

