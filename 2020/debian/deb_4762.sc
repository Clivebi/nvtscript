if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704762" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-24660" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-18 19:42:00 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-10 07:28:26 +0000 (Thu, 10 Sep 2020)" );
	script_name( "Debian: Security Advisory for lemonldap-ng (DSA-4762-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4762.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4762-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lemonldap-ng'
  package(s) announced via the DSA-4762-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the default configuration files for running the
Lemonldap::NG Web SSO system on the Nginx web server were susceptible
to authorisation bypass of URL access rules. The Debian packages do not
use Nginx by default." );
	script_tag( name: "affected", value: "'lemonldap-ng' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 2.0.2+ds-7+deb10u5, this update provides fixed example
configuration which needs to be integrated into Lemonldap::NG
deployments based on Nginx.

We recommend that you upgrade your lemonldap-ng packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-doc", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-fastcgi-server", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-handler", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-uwsgi-app", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-common-perl", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-handler-perl", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-manager-perl", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-portal-perl", ver: "2.0.2+ds-7+deb10u5", rls: "DEB10" ) )){
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

