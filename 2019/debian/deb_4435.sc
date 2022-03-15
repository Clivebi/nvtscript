if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704435" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-7317" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-04-28 02:00:07 +0000 (Sun, 28 Apr 2019)" );
	script_name( "Debian Security Advisory DSA 4435-1 (libpng1.6 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4435.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4435-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng1.6'
  package(s) announced via the DSA-4435-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A use-after-free vulnerability was discovered in the png_image_free()
function in the libpng PNG library, which could lead to denial of
service or potentially the execution of arbitrary code if a malformed
image is processed." );
	script_tag( name: "affected", value: "'libpng1.6' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.6.28-1+deb9u1.

We recommend that you upgrade your libpng1.6 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libpng-dev", ver: "1.6.28-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpng-tools", ver: "1.6.28-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpng16-16", ver: "1.6.28-1+deb9u1", rls: "DEB9" ) )){
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

