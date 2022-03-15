if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704662" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2767", "CVE-2020-2773", "CVE-2020-2778", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2816", "CVE-2020-2830" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-02 15:15:00 +0000 (Tue, 02 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-04-25 03:00:30 +0000 (Sat, 25 Apr 2020)" );
	script_name( "Debian: Security Advisory for openjdk-11 (DSA-4662-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4662.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4662-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-11'
  package(s) announced via the DSA-4662-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the OpenJDK Java
runtime, resulting in denial of service, insecure TLS handshakes, bypass
of sandbox restrictions or HTTP response splitting attacks." );
	script_tag( name: "affected", value: "'openjdk-11' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 11.0.7+10-3~deb10u1.

We recommend that you upgrade your openjdk-11 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-dbg", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-demo", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-doc", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk-headless", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-source", ver: "11.0.7+10-3~deb10u1", rls: "DEB10" ) )){
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

