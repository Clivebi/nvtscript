if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892587" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-20272", "CVE-2021-20273", "CVE-2021-20275", "CVE-2021-20276" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 07:15:00 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 04:00:09 +0000 (Wed, 10 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for privoxy (DLA-2587-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2587-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2587-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'privoxy'
  package(s) announced via the DLA-2587-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in privoxy, a web proxy with
advanced filtering capabilities.

CVE-2021-20272

An assertion failure could be triggered with a crafted CGI
request leading to server crash.

CVE-2021-20273

A crash can occur via a crafted CGI request if Privoxy is toggled
off.

CVE-2021-20275

An invalid read of size two may occur in
chunked_body_is_complete() leading to denial of service.

CVE-2021-20276

Invalid memory access with an invalid pattern passed to
pcre_compile() may lead to denial of service." );
	script_tag( name: "affected", value: "'privoxy' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
3.0.26-3+deb9u2.

We recommend that you upgrade your privoxy packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "privoxy", ver: "3.0.26-3+deb9u2", rls: "DEB9" ) )){
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

