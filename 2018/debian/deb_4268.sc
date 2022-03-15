if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704268" );
	script_version( "2021-06-17T11:57:04+0000" );
	script_cve_id( "CVE-2018-2952" );
	script_name( "Debian Security Advisory DSA 4268-1 (openjdk-8 - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:57:04 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-10 00:00:00 +0200 (Fri, 10 Aug 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4268.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "openjdk-8 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 8u181-b13-1~deb9u1.

We recommend that you upgrade your openjdk-8 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/openjdk-8" );
	script_tag( name: "summary", value: "It was discovered that the PatternSyntaxException class in the
Concurrency component of OpenJDK, an implementation of the Oracle Java
platform could result in denial of service via excessive memory
consumption." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-dbg", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-demo", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-doc", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-source", ver: "8u181-b13-1~deb9u1", rls: "DEB9" ) )){
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

