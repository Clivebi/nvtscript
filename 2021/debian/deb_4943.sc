if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704943" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-35472" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-11 15:31:00 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-24 03:00:05 +0000 (Sat, 24 Jul 2021)" );
	script_name( "Debian: Security Advisory for lemonldap-ng (DSA-4943-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4943.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4943-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4943-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lemonldap-ng'
  package(s) announced via the DSA-4943-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in lemonldap-ng, a Web-SSO
system. The flaws could result in information disclosure, authentication
bypass, or could allow an attacker to increase its authentication level
or impersonate another user, especially when lemonldap-ng is configured
to increase authentication level for users authenticated via a second
factor." );
	script_tag( name: "affected", value: "'lemonldap-ng' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 2.0.2+ds-7+deb10u6.

We recommend that you upgrade your lemonldap-ng packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-doc", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-fastcgi-server", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-handler", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lemonldap-ng-uwsgi-app", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-common-perl", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-handler-perl", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-manager-perl", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblemonldap-ng-portal-perl", ver: "2.0.2+ds-7+deb10u6", rls: "DEB10" ) )){
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

