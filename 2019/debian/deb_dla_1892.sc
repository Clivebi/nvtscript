if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891892" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2018-1000656" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-09 22:15:00 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2019-08-22 02:00:07 +0000 (Thu, 22 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for flask (DLA-1892-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00025.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1892-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'flask'
  package(s) announced via the DLA-1892-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Flask, a micro web framework for Python contains a CWE-20: Improper
Input Validation vulnerability that can result in Large amount of
memory usage possibly leading to denial of service. This attack appear
to be exploitable via Attacker provides JSON data in incorrect encoding." );
	script_tag( name: "affected", value: "'flask' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.10.1-2+deb8u1.

We recommend that you upgrade your flask packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-flask", ver: "0.10.1-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-flask-doc", ver: "0.10.1-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-flask", ver: "0.10.1-2+deb8u1", rls: "DEB8" ) )){
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

