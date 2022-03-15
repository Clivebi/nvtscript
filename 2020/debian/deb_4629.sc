if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704629" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-7471" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-19 03:15:00 +0000 (Fri, 19 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-02-20 04:00:13 +0000 (Thu, 20 Feb 2020)" );
	script_name( "Debian: Security Advisory for python-django (DSA-4629-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4629.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4629-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-django'
  package(s) announced via the DSA-4629-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Simon Charette discovered that Django, a high-level Python web
development framework, did not properly handle input in its PostgreSQL
module. A remote attacker could leverage this to perform SQL injection
attacks." );
	script_tag( name: "affected", value: "'python-django' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 1:1.10.7-2+deb9u8.

For the stable distribution (buster), this problem has been fixed in
version 1:1.11.28-1~deb10u1.

We recommend that you upgrade your python-django packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1:1.11.28-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-common", ver: "1:1.11.28-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-doc", ver: "1:1.11.28-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "1:1.11.28-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1:1.10.7-2+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-common", ver: "1:1.10.7-2+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-doc", ver: "1:1.10.7-2+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "1:1.10.7-2+deb9u8", rls: "DEB9" ) )){
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

