if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892618" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2018-13982", "CVE-2021-26119", "CVE-2021-26120" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 10:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-06 03:00:10 +0000 (Tue, 06 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for smarty3 (DLA-2618-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/04/msg00004.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2618-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2618-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'smarty3'
  package(s) announced via the DLA-2618-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in smarty3, a template engine
for PHP.

CVE-2018-13982

path traversal vulnerability due to insufficient sanitization of
code in Smarty templates. This allows attackers controlling the
Smarty template to bypass the trusted directory security
restriction and read arbitrary files.

CVE-2021-26119

allows a Sandbox Escape because $smarty.template_object can be
accessed in sandbox mode.

CVE-2021-26120

allows code injection vulnerability via an unexpected function
name after a {function name= substring." );
	script_tag( name: "affected", value: "'smarty3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u2.

We recommend that you upgrade your smarty3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "smarty3", ver: "3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u2", rls: "DEB9" ) )){
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

