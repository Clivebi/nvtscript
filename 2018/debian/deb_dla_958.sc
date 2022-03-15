if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890958" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2017-9224", "CVE-2017-9226", "CVE-2017-9227", "CVE-2017-9228", "CVE-2017-9229" );
	script_name( "Debian LTS: Security Advisory for libonig (DLA-958-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-31 10:30:00 +0000 (Wed, 31 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/05/msg00029.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libonig on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
5.9.1-1+deb7u1.

We recommend that you upgrade your libonig packages." );
	script_tag( name: "summary", value: "CVE-2017-9224

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack
out-of-bounds read occurs in match_at() during regular expression
searching. A logical error involving order of validation and access in
match_at() could result in an out-of-bounds read from a stack buffer.

CVE-2017-9226

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap
out-of-bounds write or read occurs in next_state_val() during regular
expression compilation. Octal numbers larger than 0xff are not handled
correctly in fetch_token() and fetch_token_in_cc(). A malformed regular
expression containing an octal number in the form of '\\700' would
produce an invalid code point value larger than 0xff in
next_state_val(), resulting in an out-of-bounds write memory
corruption.

CVE-2017-9227

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack
out-of-bounds read occurs in mbc_enc_len() during regular expression
searching. Invalid handling of reg->dmin in forward_search_range()
could result in an invalid pointer dereference, as an out-of-bounds
read from a stack buffer.

CVE-2017-9228

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap
out-of-bounds write occurs in bitset_set_range() during regular
expression compilation due to an uninitialized variable from an
incorrect state transition. An incorrect state transition in
parse_char_class() could create an execution path that leaves a
critical local variable uninitialized until it's used as an index,
resulting in an out-of-bounds write memory corruption.

CVE-2017-9229

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A SIGSEGV occurs
in left_adjust_char_head() during regular expression compilation.
Invalid handling of reg->dmax in forward_search_range() could result in
an invalid pointer dereference, normally as an immediate
denial-of-service condition." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libonig-dev", ver: "5.9.1-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libonig2", ver: "5.9.1-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libonig2-dbg", ver: "5.9.1-1+deb7u1", rls: "DEB7" ) )){
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

