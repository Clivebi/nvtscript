if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704348" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2018-0732", "CVE-2018-0734", "CVE-2018-0735", "CVE-2018-0737", "CVE-2018-5407" );
	script_name( "Debian Security Advisory DSA 4348-1 (openssl - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-30 00:00:00 +0100 (Fri, 30 Nov 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-08 12:15:00 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4348.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1.1.0j-1~deb9u1. Going forward, openssl security updates for
stretch will be based on the 1.1.0x upstream releases.

We recommend that you upgrade your openssl packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/openssl" );
	script_tag( name: "summary", value: "Several local side channel attacks and a denial of service via large
Diffie-Hellman parameters were discovered in OpenSSL, a Secure Sockets
Layer toolkit." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.1.0j-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.0j-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.1.0j-1~deb9u1", rls: "DEB9" ) )){
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

