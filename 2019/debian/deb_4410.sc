if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704410" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-2422" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-03-19 22:00:00 +0000 (Tue, 19 Mar 2019)" );
	script_name( "Debian Security Advisory DSA 4410-1 (openjdk-8 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4410.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4410-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the DSA-4410-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A memory disclosure vulnerability was discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in information
disclosure or bypass of sandbox restrictions." );
	script_tag( name: "affected", value: "'openjdk-8' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 8u212-b01-1~deb9u1.

We recommend that you upgrade your openjdk-8 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-dbg", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-demo", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-doc", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-source", ver: "8u212-b01-1~deb9u1", rls: "DEB9" ) )){
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

