if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704972" );
	script_version( "2021-09-11T01:00:04+0000" );
	script_cve_id( "CVE-2021-3781" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-11 01:00:04 +0000 (Sat, 11 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-11 01:00:04 +0000 (Sat, 11 Sep 2021)" );
	script_name( "Debian: Security Advisory for ghostscript (DSA-4972-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB11" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4972.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4972-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4972-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript'
  package(s) announced via the DSA-4972-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ghostscript, the GPL PostScript/PDF interpreter,
does not properly validate access for the '%pipe%', '%handle%' and
'%printer%' io devices, which could result in the execution of arbitrary
code if a malformed Postscript file is processed (despite the -dSAFER
sandbox being enabled)." );
	script_tag( name: "affected", value: "'ghostscript' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (bullseye), this problem has been fixed in
version 9.53.3~dfsg-7+deb11u1.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.53.3~dfsg-7+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.53.3~dfsg-7+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.53.3~dfsg-7+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.53.3~dfsg-7+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.53.3~dfsg-7+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.53.3~dfsg-7+deb11u1", rls: "DEB11" ) )){
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

