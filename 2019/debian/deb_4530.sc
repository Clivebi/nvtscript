if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704530" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-15903" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 23:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-09-23 02:00:06 +0000 (Mon, 23 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4530-1 (expat - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4530.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4530-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'expat'
  package(s) announced via the DSA-4530-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Expat, an XML parsing C library, did not properly
handled internal entities closing the doctype, potentially resulting in
denial of service or information disclosure if a malformed XML file is
processed." );
	script_tag( name: "affected", value: "'expat' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 2.2.0-2+deb9u3.

For the stable distribution (buster), this problem has been fixed in
version 2.2.6-2+deb10u1.

We recommend that you upgrade your expat packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "expat", ver: "2.2.6-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexpat1", ver: "2.2.6-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexpat1-dev", ver: "2.2.6-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "expat", ver: "2.2.0-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lib64expat1", ver: "2.2.0-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lib64expat1-dev", ver: "2.2.0-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexpat1", ver: "2.2.0-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexpat1-dev", ver: "2.2.0-2+deb9u3", rls: "DEB9" ) )){
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

