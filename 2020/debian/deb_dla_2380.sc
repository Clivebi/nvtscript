if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892380" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-25739" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 23:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-27 03:00:19 +0000 (Sun, 27 Sep 2020)" );
	script_name( "Debian LTS: Security Advisory for ruby-gon (DLA-2380-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/09/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2380-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/970938" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-gon'
  package(s) announced via the DLA-2380-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a cross-site scripting (XSS)
vulnerability in ruby-gon, a Ruby library to send/convert data to
Javascript from a Ruby application." );
	script_tag( name: "affected", value: "'ruby-gon' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
6.1.0-1+deb9u1.

We recommend that you upgrade your ruby-gon packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-gon", ver: "6.1.0-1+deb9u1", rls: "DEB9" ) )){
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

