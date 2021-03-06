if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704489" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-13636", "CVE-2019-13638" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-16 12:15:00 +0000 (Fri, 16 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-07-28 02:00:06 +0000 (Sun, 28 Jul 2019)" );
	script_name( "Debian Security Advisory DSA 4489-1 (patch - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4489.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4489-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'patch'
  package(s) announced via the DSA-4489-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Imre Rad discovered several vulnerabilities in GNU patch, leading to
shell command injection or escape from the working directory and access
and overwrite files, if specially crafted patch files are processed.

This update includes a bugfix for a regression introduced by the patch
to address CVE-2018-1000156
when applying an ed-style patch (#933140)." );
	script_tag( name: "affected", value: "'patch' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 2.7.5-1+deb9u2.

For the stable distribution (buster), these problems have been fixed in
version 2.7.6-3+deb10u1.

We recommend that you upgrade your patch packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "patch", ver: "2.7.6-3+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "patch", ver: "2.7.5-1+deb9u2", rls: "DEB9" ) )){
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

