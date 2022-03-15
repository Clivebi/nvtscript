if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704480" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-10192", "CVE-2019-10193" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-07-13 02:00:06 +0000 (Sat, 13 Jul 2019)" );
	script_name( "Debian Security Advisory DSA 4480-1 (redis - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4480.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4480-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'redis'
  package(s) announced via the DSA-4480-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in the HyperLogLog implementation
of Redis, a persistent key-value database, which could result in denial
of service or potentially the execution of arbitrary code." );
	script_tag( name: "affected", value: "'redis' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 3:3.2.6-3+deb9u3.

For the stable distribution (buster), these problems have been fixed in
version 5:5.0.3-4+deb10u1.

We recommend that you upgrade your redis packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "redis", ver: "5:5.0.3-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-sentinel", ver: "5:5.0.3-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-server", ver: "5:5.0.3-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-tools", ver: "5:5.0.3-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-sentinel", ver: "3:3.2.6-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-server", ver: "3:3.2.6-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-tools", ver: "3:3.2.6-3+deb9u3", rls: "DEB9" ) )){
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

