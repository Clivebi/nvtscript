if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892707" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-33054" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 22:15:00 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:00:09 +0000 (Tue, 13 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for sogo (DLA-2707-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2707-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2707-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sogo'
  package(s) announced via the DLA-2707-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "One security issue has been discovered in sogo.

SOGo does not validate the signatures of any SAML assertions it receives.
Any actor with network access to the deployment could impersonate users when
SAML is the authentication method." );
	script_tag( name: "affected", value: "'sogo' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
3.2.6-2+deb9u1.

We recommend that you upgrade your sogo packages.

ATTENTION! If you are using SAML authentication, use sogo-tool to immediately
delete users sessions and force all users to visit the login page:

sogo-tool -v expire-sessions 1
systemctl restart memcached" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sogo", ver: "3.2.6-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sogo-common", ver: "3.2.6-2+deb9u1", rls: "DEB9" ) )){
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

