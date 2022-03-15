if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892216" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2020-8161" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 23:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-05-23 03:00:09 +0000 (Sat, 23 May 2020)" );
	script_name( "Debian LTS: Security Advisory for ruby-rack (DLA-2216-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2216-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-rack'
  package(s) announced via the DLA-2216-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "There was a possible directory traversal vulnerability in the
Rack::Directory app that is bundled with Rack.

If certain directories exist in a director that is managed by
`Rack::Directory`, an attacker could, using this vulnerability,
read the contents of files on the server that were outside of
the root specified in the Rack::Directory initializer." );
	script_tag( name: "affected", value: "'ruby-rack' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.5.2-3+deb8u3.

We recommend that you upgrade your ruby-rack packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-rack", ver: "1.5.2-3+deb8u3", rls: "DEB8" ) )){
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

