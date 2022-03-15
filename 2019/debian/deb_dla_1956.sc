if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891956" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-11027" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-14 12:29:00 +0000 (Fri, 14 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-10-12 02:00:06 +0000 (Sat, 12 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for ruby-openid (DLA-1956-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1956-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-openid'
  package(s) announced via the DLA-1956-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ruby-openid performed discovery first, and then verification. This allowed an
attacker to change the URL used for discovery and trick the server into
connecting to the URL. This server in turn could be a private server not
publicly accessible.

Furthermore, if the client that uses this library discloses connection errors,
this in turn could disclose information from the private server to the
attacker." );
	script_tag( name: "affected", value: "'ruby-openid' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.5.0debian-1+deb8u1.

We recommend that you upgrade your ruby-openid packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-openid", ver: "2.5.0debian-1+deb8u1", rls: "DEB8" ) )){
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

