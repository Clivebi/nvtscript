if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703760" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_cve_id( "CVE-2016-10026", "CVE-2016-9646", "CVE-2017-0356" );
	script_name( "Debian Security Advisory DSA 3760-1 (ikiwiki - security update)" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-12 00:00:00 +0100 (Thu, 12 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-18 15:40:00 +0000 (Fri, 18 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3760.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ikiwiki on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these
problems have been fixed in version 3.20141016.4.

For the unstable distribution (sid), these problems have been fixed in
version 3.20170111.

We recommend that you upgrade your ikiwiki packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found in
the Ikiwiki wiki compiler:

CVE-2016-9646
Commit metadata forgery via CGI::FormBuilder context-dependent APIs

CVE-2016-10026
Editing restriction bypass for git revert

CVE-2017-0356
Authentication bypass via repeated parameters." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ikiwiki", ver: "3.20141016.4", rls: "DEB8" ) ) != NULL){
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

