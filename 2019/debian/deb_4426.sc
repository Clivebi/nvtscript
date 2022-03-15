if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704426" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-10868" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-26 12:45:00 +0000 (Wed, 26 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-08 02:00:09 +0000 (Mon, 08 Apr 2019)" );
	script_name( "Debian Security Advisory DSA 4426-1 (tryton-server - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4426.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4426-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tryton-server'
  package(s) announced via the DSA-4426-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Cedric Krier discovered that missing access validation in Tryton could
result in information disclosure ." );
	script_tag( name: "affected", value: "'tryton-server' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 4.2.1-2+deb9u1.

We recommend that you upgrade your tryton-server packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "tryton-server", ver: "4.2.1-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tryton-server-doc", ver: "4.2.1-2+deb9u1", rls: "DEB9" ) )){
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

