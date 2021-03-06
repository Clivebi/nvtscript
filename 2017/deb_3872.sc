if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703872" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-7502" );
	script_name( "Debian Security Advisory DSA 3872-1 (nss - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-01 00:00:00 +0200 (Thu, 01 Jun 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3872.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "nss on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 2:3.26-1+debu8u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your nss packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in NSS, a set of cryptographic
libraries, which may result in denial of service or information
disclosure." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.26-1+debu8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "2:3.26-1+debu8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dbg", ver: "2:3.26-1+debu8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "2:3.26-1+debu8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "2:3.26-1+debu8u2", rls: "DEB8" ) ) != NULL){
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

