if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704851" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-17525" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 09:15:00 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2021-02-14 04:00:35 +0000 (Sun, 14 Feb 2021)" );
	script_name( "Debian: Security Advisory for subversion (DSA-4851-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4851.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4851-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4851-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'subversion'
  package(s) announced via the DSA-4851-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Thomas Akesson discovered a remotely triggerable vulnerability in the
mod_authz_svn module in Subversion, a version control system. When using
in-repository authz rules with the AuthzSVNReposRelativeAccessFile
option an unauthenticated remote client can take advantage of this flaw
to cause a denial of service by sending a request for a non-existing
repository URL." );
	script_tag( name: "affected", value: "'subversion' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.10.4-1+deb10u2.

We recommend that you upgrade your subversion packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-svn", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsvn-dev", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsvn-doc", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsvn-java", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsvn-perl", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsvn1", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-subversion", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-svn", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "subversion", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "subversion-tools", ver: "1.10.4-1+deb10u2", rls: "DEB10" ) )){
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

