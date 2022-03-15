if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704521" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-13139", "CVE-2019-13509", "CVE-2019-14271" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-28 13:15:00 +0000 (Wed, 28 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-09-11 02:00:11 +0000 (Wed, 11 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4521-1 (docker.io - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4521.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4521-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'docker.io'
  package(s) announced via the DSA-4521-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Three security vulnerabilities have been discovered in the Docker
container runtime: Insecure loading of NSS libraries in docker cp could result in execution of code with root privileges, sensitive data
could be logged in debug mode and there was a command injection
vulnerability in the docker build
command." );
	script_tag( name: "affected", value: "'docker.io' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 18.09.1+dfsg1-7.1+deb10u1.

We recommend that you upgrade your docker.io packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "docker-doc", ver: "18.09.1+dfsg1-7.1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "docker.io", ver: "18.09.1+dfsg1-7.1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-docker-dev", ver: "18.09.1+dfsg1-7.1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-github-docker-docker-dev", ver: "18.09.1+dfsg1-7.1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-syntax-docker", ver: "18.09.1+dfsg1-7.1+deb10u1", rls: "DEB10" ) )){
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

