if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892389" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-18978" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 16:47:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2020-10-02 03:00:08 +0000 (Fri, 02 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for ruby-rack-cors (DLA-2389-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2389-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/944849" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-rack-cors'
  package(s) announced via the DLA-2389-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package allowed ../ directory traversal to access private
resources because resource matching did not ensure that
pathnames were in a canonical format." );
	script_tag( name: "affected", value: "'ruby-rack-cors' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.4.0-1+deb9u2.

We recommend that you upgrade your ruby-rack-cors packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-rack-cors", ver: "0.4.0-1+deb9u2", rls: "DEB9" ) )){
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

