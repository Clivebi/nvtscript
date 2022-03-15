if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891844" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-13031" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-26 14:15:00 +0000 (Mon, 26 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-07-05 02:00:09 +0000 (Fri, 05 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for lemonldap-ng (DLA-1844-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1844-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/931117" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lemonldap-ng'
  package(s) announced via the DLA-1844-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a XML external entity vulnerability
in the lemonldap-ng single-sign on system. This may have led to the
disclosure of confidential data, denial of service, server side
request forgery, port scanning, etc." );
	script_tag( name: "affected", value: "'lemonldap-ng' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in lemonldap-ng version
1.3.3-1+deb8u2.

We recommend that you upgrade your lemonldap-ng packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng", ver: "1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-doc", ver: "1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-common-perl", ver: "1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-conf-perl", ver: "1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-handler-perl", ver: "1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-manager-perl", ver: "1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-portal-perl", ver: "1.3.3-1+deb8u2", rls: "DEB8" ) )){
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

