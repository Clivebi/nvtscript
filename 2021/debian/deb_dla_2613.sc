if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892613" );
	script_version( "2021-09-24T12:22:54+0000" );
	script_cve_id( "CVE-2021-23358" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-24 12:22:54 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-22 19:49:00 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-04-01 03:00:13 +0000 (Thu, 01 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for underscore (DLA-2613-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00038.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2613-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2613-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/986171" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'underscore'
  package(s) announced via the DLA-2613-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "node-underscore and libjs-underscore are vulnerable to Arbitrary Code
Execution via the template function, particularly when a variable
property is passed as an argument as it is not sanitized." );
	script_tag( name: "affected", value: "'underscore' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.8.3~dfsg-1+deb9u1.

We recommend that you upgrade your underscore packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjs-underscore", ver: "1.8.3~dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "node-underscore", ver: "1.8.3~dfsg-1+deb9u1", rls: "DEB9" ) )){
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

