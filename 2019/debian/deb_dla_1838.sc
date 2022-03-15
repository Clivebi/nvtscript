if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891838" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-5686", "CVE-2018-6192", "CVE-2019-6130" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-30 18:05:00 +0000 (Thu, 30 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-06-29 02:00:10 +0000 (Sat, 29 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for mupdf (DLA-1838-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1838-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/887130" );
	script_xref( name: "URL", value: "https://bugs.debian.org/888487" );
	script_xref( name: "URL", value: "https://bugs.debian.org/918971" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mupdf'
  package(s) announced via the DLA-1838-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several minor issues have been fixed in mupdf, a lightweight PDF viewer
tailored for display of high quality anti-aliased graphics.

CVE-2018-5686

In MuPDF, there was an infinite loop vulnerability and application
hang in the pdf_parse_array function (pdf/pdf-parse.c) because EOF
not having been considered. Remote attackers could leverage this
vulnerability to cause a denial of service via a crafted PDF file.

CVE-2019-6130

MuPDF had a SEGV in the function fz_load_page of the fitz/document.c
file, as demonstrated by mutool. This was related to page-number
mishandling in cbz/mucbz.c, cbz/muimg.c, and svg/svg-doc.c.

CVE-2018-6192

In MuPDF, the pdf_read_new_xref function in pdf/pdf-xref.c allowed
remote attackers to cause a denial of service (segmentation violation
and application crash) via a crafted PDF file." );
	script_tag( name: "affected", value: "'mupdf' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.5-1+deb8u6.

We recommend that you upgrade your mupdf packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmupdf-dev", ver: "1.5-1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mupdf", ver: "1.5-1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mupdf-tools", ver: "1.5-1+deb8u6", rls: "DEB8" ) )){
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

