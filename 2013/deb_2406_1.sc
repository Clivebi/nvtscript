if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702406" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-0449", "CVE-2012-0442", "CVE-2011-3670", "CVE-2012-0444" );
	script_name( "Debian Security Advisory DSA 2406-1 (icedove - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2406.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "icedove on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 3.0.11-1+squeeze7.

We recommend that you upgrade your icedove packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Icedove, Debian's
variant of the Mozilla Thunderbird code base.

CVE-2011-3670Icedove does not not properly enforce the IPv6 literal address
syntax, which allows remote attackers to obtain sensitive
information by making XMLHttpRequest calls through a proxy and
reading the error messages.

CVE-2012-0442Memory corruption bugs could cause Icedove to crash or
possibly execute arbitrary code.

CVE-2012-0444Icedove does not properly initialize nsChildView data
structures, which allows remote attackers to cause a denial of
service (memory corruption and application crash) or possibly
execute arbitrary code via a crafted Ogg Vorbis file.

CVE-2012-0449Icedove allows remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via a malformed XSLT stylesheet that is
embedded in a document." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedove", ver: "3.0.11-1+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "3.0.11-1+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "3.0.11-1+squeeze7", rls: "DEB6" ) ) != NULL){
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

