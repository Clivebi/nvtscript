if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704953" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_cve_id( "CVE-2021-38165" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-24 16:35:00 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-12 03:00:07 +0000 (Thu, 12 Aug 2021)" );
	script_name( "Debian: Security Advisory for lynx (DSA-4953-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4953.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4953-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4953-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lynx'
  package(s) announced via the DSA-4953-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Thorsten Glaser and Axel Beckert reported that lynx, a non-graphical
(text-mode) web browser, does not properly handle the userinfo
subcomponent of a URI, which can lead to leaking of credential in
cleartext in SNI data." );
	script_tag( name: "affected", value: "'lynx' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 2.8.9rel.1-3+deb10u1.

We recommend that you upgrade your lynx packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lynx", ver: "2.8.9rel.1-3+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lynx-common", ver: "2.8.9rel.1-3+deb10u1", rls: "DEB10" ) )){
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

