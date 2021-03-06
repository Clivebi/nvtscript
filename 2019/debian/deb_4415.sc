if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704415" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2017-16355" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-28 15:31:00 +0000 (Mon, 28 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-03-23 22:00:00 +0000 (Sat, 23 Mar 2019)" );
	script_name( "Debian Security Advisory DSA 4415-1 (passenger - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4415.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4415-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'passenger'
  package(s) announced via the DSA-4415-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An arbitrary file read vulnerability was discovered in passenger, a web
application server. A local user allowed to deploy an application to
passenger, can take advantage of this flaw by creating a symlink from
the REVISION file to an arbitrary file on the system and have its
content displayed through passenger-status." );
	script_tag( name: "affected", value: "'passenger' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 5.0.30-1+deb9u1.

We recommend that you upgrade your passenger packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-passenger", ver: "5.0.30-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "passenger", ver: "5.0.30-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "passenger-doc", ver: "5.0.30-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-passenger", ver: "5.0.30-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-passenger-doc", ver: "5.0.30-1+deb9u1", rls: "DEB9" ) )){
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

