if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704919" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-3520" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-22 03:00:04 +0000 (Sat, 22 May 2021)" );
	script_name( "Debian: Security Advisory for lz4 (DSA-4919-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4919.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4919-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4919-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lz4'
  package(s) announced via the DSA-4919-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jasper Lievisse Adriaanse reported an integer overflow flaw in lz4, a
fast LZ compression algorithm library, resulting in memory corruption." );
	script_tag( name: "affected", value: "'lz4' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.8.3-1+deb10u1.

We recommend that you upgrade your lz4 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblz4-1", ver: "1.8.3-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblz4-dev", ver: "1.8.3-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblz4-tool", ver: "1.8.3-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lz4", ver: "1.8.3-1+deb10u1", rls: "DEB10" ) )){
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

