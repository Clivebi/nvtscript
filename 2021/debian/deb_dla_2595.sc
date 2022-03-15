if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892595" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-13936" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-01 08:15:00 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-18 04:00:07 +0000 (Thu, 18 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for velocity (DLA-2595-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2595-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2595-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/985220" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'velocity'
  package(s) announced via the DLA-2595-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a potential arbitrary code execution
vulnerability in velocity, a Java-based template engine for writing
web applications. It could be exploited by applications which allowed
untrusted users to upload/modify templates." );
	script_tag( name: "affected", value: "'velocity' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
1.7-5+deb9u1.

We recommend that you upgrade your velocity packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "velocity", ver: "1.7-5+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "velocity-doc", ver: "1.7-5+deb9u1", rls: "DEB9" ) )){
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

