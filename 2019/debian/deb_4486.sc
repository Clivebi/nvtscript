if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704486" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2818", "CVE-2019-2821" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-07-24 02:00:48 +0000 (Wed, 24 Jul 2019)" );
	script_name( "Debian Security Advisory DSA 4486-1 (openjdk-11 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4486.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4486-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-11'
  package(s) announced via the DSA-4486-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the OpenJDK Java runtime,
resulting in information disclosure, denial of service or bypass of
sandbox restrictions. In addition the implementation of elliptic curve
cryptography was modernised." );
	script_tag( name: "affected", value: "'openjdk-11' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 11.0.4+11-1~deb10u1.

We recommend that you upgrade your openjdk-11 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-dbg", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-demo", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-doc", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk-headless", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-source", ver: "11.0.4+11-1~deb10u1", rls: "DEB10" ) )){
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

