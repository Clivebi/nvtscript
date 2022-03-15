if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892232" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2020-11078" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-19 18:56:00 +0000 (Wed, 19 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-06-02 03:00:06 +0000 (Tue, 02 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for python-httplib2 (DLA-2232-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2232-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-httplib2'
  package(s) announced via the DLA-2232-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In httplib2, an attacker controlling unescaped part of uri for
`httplib2.Http.request()` could change request headers and body, send
additional hidden requests to same server. This vulnerability impacts
software that uses httplib2 with uri constructed by string
concatenation, as opposed to proper urllib building with escaping." );
	script_tag( name: "affected", value: "'python-httplib2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.9+dfsg-2+deb8u1.

We recommend that you upgrade your python-httplib2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-httplib2", ver: "0.9+dfsg-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-httplib2", ver: "0.9+dfsg-2+deb8u1", rls: "DEB8" ) )){
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

