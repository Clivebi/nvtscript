if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704976" );
	script_version( "2021-09-23T08:01:25+0000" );
	script_cve_id( "CVE-2021-30858" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-23 08:01:25 +0000 (Thu, 23 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-15 12:55:00 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-23 01:00:06 +0000 (Thu, 23 Sep 2021)" );
	script_name( "Debian: Security Advisory for wpewebkit (DSA-4976-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB11" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4976.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4976-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4976-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wpewebkit'
  package(s) announced via the DSA-4976-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities have been discovered in the webkit2gtk
web engine:

CVE-2021-30858
An anonymous researcher discovered that processing maliciously
crafted web content may lead to arbitrary code execution. Apple is
aware of a report that this issue may have been actively
exploited." );
	script_tag( name: "affected", value: "'wpewebkit' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (bullseye), this problem has been fixed in
version 2.32.4-1~deb11u1.

We recommend that you upgrade your wpewebkit packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libwpewebkit-1.0-3", ver: "2.32.4-1~deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwpewebkit-1.0-dev", ver: "2.32.4-1~deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwpewebkit-1.0-doc", ver: "2.32.4-1~deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wpewebkit-driver", ver: "2.32.4-1~deb11u1", rls: "DEB11" ) )){
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

