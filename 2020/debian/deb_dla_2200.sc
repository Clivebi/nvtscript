if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892200" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-12137" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-27 16:15:00 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-05-04 03:00:06 +0000 (Mon, 04 May 2020)" );
	script_name( "Debian LTS: Security Advisory for mailman (DLA-2200-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2200-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mailman'
  package(s) announced via the DLA-2200-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in mailman. GNU Mailman 2.x before 2.1.30
uses the .obj extension for scrubbed application/octet-stream MIME
parts. This behavior may contribute to XSS attacks against
list-archive visitors, because an HTTP reply from an archive web
server may lack a MIME type, and a web browser may perform MIME
sniffing, conclude that the MIME type should have been text/html, and
execute JavaScript code." );
	script_tag( name: "affected", value: "'mailman' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1:2.1.18-2+deb8u5.

We recommend that you upgrade your mailman packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mailman", ver: "1:2.1.18-2+deb8u5", rls: "DEB8" ) )){
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

