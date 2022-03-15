if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704743" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-17367", "CVE-2020-17368" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-10 11:15:00 +0000 (Sun, 10 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-08-12 03:00:06 +0000 (Wed, 12 Aug 2020)" );
	script_name( "Debian: Security Advisory for ruby-kramdown (DSA-4743-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4743.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4743-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-kramdown'
  package(s) announced via the DSA-4743-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was discovered in ruby-kramdown, a fast, pure ruby, Markdown
parser and converter, which could result in unintended read access to
files or unintended embedded Ruby code execution when the {::options /}
extension is used together with the template
option.

The Update introduces a new option forbidden_inline_options to
restrict the options allowed with the {::options /} extension. By
default the template
option is forbidden." );
	script_tag( name: "affected", value: "'ruby-kramdown' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.17.0-1+deb10u1.

We recommend that you upgrade your ruby-kramdown packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-kramdown", ver: "1.17.0-1+deb10u1", rls: "DEB10" ) )){
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

