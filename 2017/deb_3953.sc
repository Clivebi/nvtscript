if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703953" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_cve_id( "CVE-2017-12440" );
	script_name( "Debian Security Advisory DSA 3953-1 (aodh - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-23 00:00:00 +0200 (Wed, 23 Aug 2017)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3953.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "aodh on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 3.0.0-4+deb9u1.

We recommend that you upgrade your aodh packages." );
	script_tag( name: "summary", value: "Zane Bitter from Red Hat discovered a vulnerability in Aodh, the alarm
engine for OpenStack. Aodh does not verify that the user creating the
alarm is the trustor or has the same rights as the trustor, nor that the
trust is for the same project as the alarm. The bug allows that an
authenticated user without a Keystone token with knowledge of trust IDs
to perform unspecified authenticated actions by adding alarm actions." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "aodh-api", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "aodh-common", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "aodh-doc", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "aodh-evaluator", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "aodh-expirer", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "aodh-listener", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "aodh-notifier", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-aodh", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
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

