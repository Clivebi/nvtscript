if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892307" );
	script_version( "2021-07-23T11:46:51+0000" );
	script_cve_id( "CVE-2018-1000544" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:46:51 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-02 03:00:14 +0000 (Sun, 02 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for ruby-zip (DLA-2307-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2307-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/902720" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-zip'
  package(s) announced via the DLA-2307-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "rubyzip gem version 1.2.1 and earlier contains a Directory Traversal
vulnerability in Zip::File component that can result in write
arbitrary files to the filesystem.

This attack appear to be exploitable via if a site allows
uploading of .zip files, an attacker can upload a malicious file
that contains symlinks or files with absolute pathnames '../'
to write arbitrary files to the filesystem." );
	script_tag( name: "affected", value: "'ruby-zip' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.2.0-1.1+deb9u1.

We recommend that you upgrade your ruby-zip packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-zip", ver: "1.2.0-1.1+deb9u1", rls: "DEB9" ) )){
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

