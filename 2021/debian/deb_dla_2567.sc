if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892567" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2017-14120", "CVE-2017-14121", "CVE-2017-14122" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 17:17:00 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-19 04:00:33 +0000 (Fri, 19 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for unrar-free (DLA-2567-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00026.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2567-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2567-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unrar-free'
  package(s) announced via the DLA-2567-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found in unrar-free, an unarchiver for .rar files.

CVE-2017-14120

This CVE is related to a directory traversal vulnerability for
RAR v2 archives.

CVE-2017-14121

This CVE is related to NULL pointer dereference flaw triggered
by a specially crafted RAR archive.

CVE-2017-14122

This CVE is related to stack-based buffer over-read." );
	script_tag( name: "affected", value: "'unrar-free' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1:0.0.1+cvs20140707-1+deb9u1.

We recommend that you upgrade your unrar-free packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "unrar-free", ver: "1:0.0.1+cvs20140707-1+deb9u1", rls: "DEB9" ) )){
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

