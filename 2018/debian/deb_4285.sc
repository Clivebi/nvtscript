if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704285" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-1000550" );
	script_name( "Debian Security Advisory DSA 4285-1 (sympa - security update)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-05 00:00:00 +0200 (Wed, 05 Sep 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-04 21:15:00 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4285.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "sympa on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 6.2.16~dfsg-3+deb9u1.

We recommend that you upgrade your sympa packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/sympa" );
	script_tag( name: "summary", value: "Michael Kaczmarczik discovered a vulnerability in the web interface
template editing function of Sympa, a mailing list manager. Owner and
listmasters could use this flaw to create or modify arbitrary files in
the server with privileges of sympa user or owner view list config files
even if edit_list.conf prohibits it." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sympa", ver: "6.2.16~dfsg-3+deb9u1", rls: "DEB9" ) )){
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

