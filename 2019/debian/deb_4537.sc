if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704537" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-16680" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-20 17:23:00 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-09-29 02:00:06 +0000 (Sun, 29 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4537-1 (file-roller - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4537.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4537-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'file-roller'
  package(s) announced via the DSA-4537-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that file-roller, an archive manager for GNOME, does
not properly handle the extraction of archives with a single ./../ in a
file path. An attacker able to provide a specially crafted archive for
processing can take advantage of this flaw to overwrite files if a user
is dragging a specific file or map to a location to extract to." );
	script_tag( name: "affected", value: "'file-roller' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 3.22.3-1+deb9u1.

We recommend that you upgrade your file-roller packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "file-roller", ver: "3.22.3-1+deb9u1", rls: "DEB9" ) )){
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

