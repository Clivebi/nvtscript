if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704586" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-15845", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-16 15:15:00 +0000 (Sun, 16 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-18 03:00:58 +0000 (Wed, 18 Dec 2019)" );
	script_name( "Debian Security Advisory DSA 4586-1 (ruby2.5 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4586.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4586-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby2.5'
  package(s) announced via the DSA-4586-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the interpreter for the
Ruby language, which could result in unauthorized access by bypassing
intended path matchings, denial of service, or the execution of
arbitrary code." );
	script_tag( name: "affected", value: "'ruby2.5' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 2.5.5-3+deb10u1.

We recommend that you upgrade your ruby2.5 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libruby2.5", ver: "2.5.5-3+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.5", ver: "2.5.5-3+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.5-dev", ver: "2.5.5-3+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.5-doc", ver: "2.5.5-3+deb10u1", rls: "DEB10" ) )){
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

